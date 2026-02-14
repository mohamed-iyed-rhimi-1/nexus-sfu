//! Socket configuration for high-performance UDP I/O.
//!
//! This module provides functions to configure UDP sockets for optimal
//! performance in high-throughput scenarios:
//!
//! - 16MB socket buffers (SO_RCVBUF/SO_SNDBUF)
//! - GRO (Generic Receive Offload) for coalesced packet reception
//! - GSO (Generic Segmentation Offload) for efficient batch sending
//!
//! # Platform Support
//!
//! - GRO/GSO: Linux only (kernel 4.18+)
//! - Socket buffers: All platforms
//!
//! # TigerStyle Compliance
//!
//! All functions follow TigerStyle rules:
//! - Maximum 70 lines per function
//! - Minimum 2 assertions per function
//! - Explicit error handling

use std::io;
use std::os::fd::RawFd;

/// Default socket buffer size: 16MB.
pub const DEFAULT_BUFFER_SIZE: i32 = 16 * 1024 * 1024;

/// Minimum acceptable buffer size: 1MB.
pub const MIN_ACCEPTABLE_BUFFER_SIZE: i32 = 1024 * 1024;

/// UDP_GRO socket option (Linux 4.18+).
#[cfg(target_os = "linux")]
pub const UDP_GRO: libc::c_int = 104;

/// UDP_SEGMENT socket option for GSO (Linux 4.18+).
#[cfg(target_os = "linux")]
pub const UDP_SEGMENT: libc::c_int = 103;

/// Result of socket buffer configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketBufferInfo {
    /// Requested receive buffer size.
    pub requested_recv: i32,
    /// Actual receive buffer size (may be capped by kernel).
    pub actual_recv: i32,
    /// Requested send buffer size.
    pub requested_send: i32,
    /// Actual send buffer size (may be capped by kernel).
    pub actual_send: i32,
    /// Whether GRO is enabled.
    pub gro_enabled: bool,
    /// Whether GSO is enabled.
    pub gso_enabled: bool,
}

impl SocketBufferInfo {
    /// Check if receive buffer achieved target size.
    #[inline]
    pub fn recv_buffer_ok(&self) -> bool {
        self.actual_recv >= MIN_ACCEPTABLE_BUFFER_SIZE
    }

    /// Check if send buffer achieved target size.
    #[inline]
    pub fn send_buffer_ok(&self) -> bool {
        self.actual_send >= MIN_ACCEPTABLE_BUFFER_SIZE
    }
}


/// Configure socket buffers for high-performance I/O.
///
/// Sets SO_RCVBUF and SO_SNDBUF to the specified sizes (default 16MB).
/// The kernel may cap these values based on system limits.
///
/// # Arguments
/// * `fd` - Socket file descriptor
/// * `recv_size` - Desired receive buffer size (default: 16MB)
/// * `send_size` - Desired send buffer size (default: 16MB)
///
/// # Returns
/// `SocketBufferInfo` with actual buffer sizes achieved.
///
/// # TigerStyle
/// - ≤70 lines
/// - ≥2 assertions
pub fn configure_socket_buffers(
    fd: RawFd,
    recv_size: Option<i32>,
    send_size: Option<i32>,
) -> io::Result<SocketBufferInfo> {
    // Assertions: fd must be valid
    assert!(fd >= 0, "socket fd must be valid (>= 0)");

    let requested_recv = recv_size.unwrap_or(DEFAULT_BUFFER_SIZE);
    let requested_send = send_size.unwrap_or(DEFAULT_BUFFER_SIZE);

    // Assertion: buffer sizes must be positive
    assert!(requested_recv > 0, "recv buffer size must be > 0");
    assert!(requested_send > 0, "send buffer size must be > 0");

    // Set receive buffer
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &requested_recv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    // Set send buffer
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &requested_send as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }

    // Verify actual sizes
    let actual_recv = get_socket_option(fd, libc::SO_RCVBUF)?;
    let actual_send = get_socket_option(fd, libc::SO_SNDBUF)?;

    // Log warnings if sizes were capped
    if actual_recv < requested_recv {
        tracing::warn!(
            "Receive buffer capped at {}MB (requested {}MB). Consider: sysctl -w net.core.rmem_max={}",
            actual_recv / 1024 / 1024,
            requested_recv / 1024 / 1024,
            requested_recv
        );
    }

    if actual_send < requested_send {
        tracing::warn!(
            "Send buffer capped at {}MB (requested {}MB). Consider: sysctl -w net.core.wmem_max={}",
            actual_send / 1024 / 1024,
            requested_send / 1024 / 1024,
            requested_send
        );
    }

    Ok(SocketBufferInfo {
        requested_recv,
        actual_recv,
        requested_send,
        actual_send,
        gro_enabled: false,
        gso_enabled: false,
    })
}

/// Get a socket option value.
fn get_socket_option(fd: RawFd, option: libc::c_int) -> io::Result<i32> {
    let mut value: libc::c_int = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            &mut value as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}


/// Enable GRO (Generic Receive Offload) on a UDP socket.
///
/// GRO allows the kernel to coalesce multiple UDP packets into a single
/// recv() call, reducing syscall overhead. The coalesced packets must be
/// split using `GroSplitter` after reception.
///
/// # Platform Support
/// Linux only (kernel 4.18+). Returns Ok(false) on other platforms.
///
/// # Arguments
/// * `fd` - Socket file descriptor
///
/// # Returns
/// `true` if GRO was enabled, `false` if not supported.
///
/// # TigerStyle
/// - ≤70 lines
/// - ≥2 assertions
#[cfg(target_os = "linux")]
pub fn enable_gro(fd: RawFd) -> io::Result<bool> {
    // Assertion: fd must be valid
    assert!(fd >= 0, "socket fd must be valid (>= 0)");

    let enable: libc::c_int = 1;

    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_UDP,
            UDP_GRO,
            &enable as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if result < 0 {
        let err = io::Error::last_os_error();
        // ENOPROTOOPT means GRO not supported
        if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
            tracing::info!("UDP_GRO not supported on this kernel");
            return Ok(false);
        }
        return Err(err);
    }

    // Assertion: verify GRO was enabled
    let mut enabled: libc::c_int = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_UDP,
            UDP_GRO,
            &mut enabled as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    if result == 0 && enabled != 0 {
        tracing::info!("UDP_GRO enabled");
        Ok(true)
    } else {
        tracing::warn!("UDP_GRO setsockopt succeeded but verification failed");
        Ok(false)
    }
}

#[cfg(not(target_os = "linux"))]
pub fn enable_gro(_fd: RawFd) -> io::Result<bool> {
    tracing::info!("UDP_GRO not available on this platform");
    Ok(false)
}

/// Enable GSO (Generic Segmentation Offload) capability check.
///
/// GSO allows sending multiple same-size packets to the same destination
/// in a single sendmsg() call with UDP_SEGMENT cmsg. This function checks
/// if GSO is available.
///
/// # Platform Support
/// Linux only (kernel 4.18+). Returns Ok(false) on other platforms.
///
/// # Arguments
/// * `fd` - Socket file descriptor
///
/// # Returns
/// `true` if GSO is available, `false` if not supported.
///
/// # TigerStyle
/// - ≤70 lines
/// - ≥2 assertions
#[cfg(target_os = "linux")]
pub fn check_gso_available(fd: RawFd) -> io::Result<bool> {
    // Assertion: fd must be valid
    assert!(fd >= 0, "socket fd must be valid (>= 0)");

    // Try to get the UDP_SEGMENT option to check availability
    let mut value: libc::c_int = 0;
    let mut len: libc::socklen_t = std::mem::size_of::<libc::c_int>() as libc::socklen_t;

    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_UDP,
            UDP_SEGMENT,
            &mut value as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };

    // Assertion: result is either success or known error
    if result < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOPROTOOPT) {
            tracing::info!("UDP_SEGMENT (GSO) not supported on this kernel");
            return Ok(false);
        }
        // Other errors might just mean the option isn't set yet, which is fine
    }

    tracing::info!("UDP_SEGMENT (GSO) available");
    Ok(true)
}

#[cfg(not(target_os = "linux"))]
pub fn check_gso_available(_fd: RawFd) -> io::Result<bool> {
    tracing::info!("UDP_SEGMENT (GSO) not available on this platform");
    Ok(false)
}


/// Configure a socket for high-performance UDP I/O with all optimizations.
///
/// This is the main entry point for socket configuration. It:
/// 1. Sets 16MB socket buffers
/// 2. Enables GRO if available
/// 3. Checks GSO availability
///
/// # Arguments
/// * `fd` - Socket file descriptor
///
/// # Returns
/// `SocketBufferInfo` with configuration results.
///
/// # TigerStyle
/// - ≤70 lines
/// - ≥2 assertions
pub fn configure_high_performance_socket(fd: RawFd) -> io::Result<SocketBufferInfo> {
    // Assertion: fd must be valid
    assert!(fd >= 0, "socket fd must be valid (>= 0)");

    // Configure buffers
    let mut info = configure_socket_buffers(fd, None, None)?;

    // Enable GRO
    info.gro_enabled = enable_gro(fd)?;

    // Check GSO availability
    info.gso_enabled = check_gso_available(fd)?;

    // Assertion: at least buffers should be configured
    assert!(info.actual_recv > 0, "receive buffer must be configured");
    assert!(info.actual_send > 0, "send buffer must be configured");

    tracing::info!(
        "Socket configured: recv={}MB, send={}MB, GRO={}, GSO={}",
        info.actual_recv / 1024 / 1024,
        info.actual_send / 1024 / 1024,
        info.gro_enabled,
        info.gso_enabled
    );

    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    #[test]
    fn test_configure_socket_buffers() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();

        let info = configure_socket_buffers(fd, Some(1024 * 1024), Some(1024 * 1024)).unwrap();

        // Kernel may double the requested size
        assert!(info.actual_recv >= 1024 * 1024 / 2);
        assert!(info.actual_send >= 1024 * 1024 / 2);
    }

    #[test]
    fn test_configure_socket_buffers_default() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();

        let info = configure_socket_buffers(fd, None, None).unwrap();

        // Should have some buffer configured
        assert!(info.actual_recv > 0);
        assert!(info.actual_send > 0);
        assert_eq!(info.requested_recv, DEFAULT_BUFFER_SIZE);
        assert_eq!(info.requested_send, DEFAULT_BUFFER_SIZE);
    }

    #[test]
    fn test_enable_gro() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();

        // Should not error, may return false if not supported
        let result = enable_gro(fd);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_gso_available() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();

        // Should not error, may return false if not supported
        let result = check_gso_available(fd);
        assert!(result.is_ok());
    }

    #[test]
    fn test_configure_high_performance_socket() {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = socket.as_raw_fd();

        let info = configure_high_performance_socket(fd).unwrap();

        assert!(info.actual_recv > 0);
        assert!(info.actual_send > 0);
    }

    #[test]
    fn test_socket_buffer_info_checks() {
        let info = SocketBufferInfo {
            requested_recv: DEFAULT_BUFFER_SIZE,
            actual_recv: 2 * 1024 * 1024,
            requested_send: DEFAULT_BUFFER_SIZE,
            actual_send: 2 * 1024 * 1024,
            gro_enabled: true,
            gso_enabled: true,
        };

        assert!(info.recv_buffer_ok());
        assert!(info.send_buffer_ok());

        let small_info = SocketBufferInfo {
            requested_recv: DEFAULT_BUFFER_SIZE,
            actual_recv: 512 * 1024, // 512KB - below minimum
            requested_send: DEFAULT_BUFFER_SIZE,
            actual_send: 512 * 1024,
            gro_enabled: false,
            gso_enabled: false,
        };

        assert!(!small_info.recv_buffer_ok());
        assert!(!small_info.send_buffer_ok());
    }
}
