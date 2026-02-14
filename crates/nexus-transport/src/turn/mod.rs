//! TURN (Traversal Using Relays around NAT) implementation.
//!
//! RFC 5766 compliant implementation for NAT traversal when direct
//! peer-to-peer connectivity fails.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       TURN Client                                │
//! ├─────────────────────────────────────────────────────────────────┤
//! │                                                                  │
//! │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
//! │  │  Allocation  │  │  Permissions │  │   Channels   │          │
//! │  │   Manager    │──▶│    Table     │──▶│   Bindings   │          │
//! │  └──────────────┘  └──────────────┘  └──────────────┘          │
//! │         │                 │                  │                  │
//! │         ▼                 ▼                  ▼                  │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │                    TURN Server                           │   │
//! │  │  (relays data between client and peers)                  │   │
//! │  └─────────────────────────────────────────────────────────┘   │
//! │                                                                  │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Message Flow
//!
//! 1. **Allocate**: Request relay address from TURN server
//! 2. **CreatePermission**: Allow traffic from specific peers
//! 3. **ChannelBind**: Optimize with channel numbers (optional)
//! 4. **Send/Data**: Relay application data
//!
//! # TigerStyle Compliance
//!
//! - All allocations have explicit lifetimes
//! - Pre-allocated permission tables
//! - No dynamic allocation on data path
//! - Comprehensive timeout handling

// TurnError uses fixed-size [u8; 128] arrays for zero-allocation on hot paths
// (TigerStyle). This makes the error type large, which is intentional.

mod allocation;
mod client;
mod error;
mod types;

pub use allocation::{Allocation, AllocationState};
pub use client::{TurnClient, TurnClientConfig};
pub use error::TurnError;
pub use types::{
    TurnCredentials, TurnServerInfo, Permission, ChannelBinding,
    RelayedAddress, TransportProtocol,
};

// ============================================================================
// Constants (RFC 5766)
// ============================================================================

/// Default TURN allocation lifetime (seconds).
/// RFC 5766 default is 600 seconds (10 minutes).
pub const DEFAULT_ALLOCATION_LIFETIME: u32 = 600;

/// Maximum allocation lifetime (seconds).
/// RFC 5766 allows up to 3600 seconds (1 hour).
pub const MAX_ALLOCATION_LIFETIME: u32 = 3600;

/// Minimum allocation lifetime (seconds).
pub const MIN_ALLOCATION_LIFETIME: u32 = 60;

/// Default permission lifetime (seconds).
/// RFC 5766 specifies 300 seconds (5 minutes).
pub const PERMISSION_LIFETIME: u32 = 300;

/// Channel binding lifetime (seconds).
/// RFC 5766 specifies 600 seconds (10 minutes).
pub const CHANNEL_BINDING_LIFETIME: u32 = 600;

/// Minimum channel number (0x4000).
pub const CHANNEL_NUMBER_MIN: u16 = 0x4000;

/// Maximum channel number (0x7FFF).
pub const CHANNEL_NUMBER_MAX: u16 = 0x7FFF;

/// Maximum permissions per allocation.
pub const MAX_PERMISSIONS: usize = 16;

/// Maximum channel bindings per allocation.
pub const MAX_CHANNEL_BINDINGS: usize = 8;

/// TURN ChannelData header size.
pub const CHANNEL_DATA_HEADER_SIZE: usize = 4;

/// Maximum data in a single TURN message.
pub const MAX_TURN_DATA_SIZE: usize = 1200;

/// Refresh margin (refresh before expiry by this amount).
pub const REFRESH_MARGIN_SECONDS: u32 = 60;

/// UDP transport protocol number.
pub const TRANSPORT_UDP: u8 = 17;

/// TCP transport protocol number.
pub const TRANSPORT_TCP: u8 = 6;

// Compile-time assertions
const _: () = {
    assert!(DEFAULT_ALLOCATION_LIFETIME >= MIN_ALLOCATION_LIFETIME);
    assert!(DEFAULT_ALLOCATION_LIFETIME <= MAX_ALLOCATION_LIFETIME);
    assert!(CHANNEL_NUMBER_MIN >= 0x4000);
    assert!(CHANNEL_NUMBER_MAX <= 0x7FFF);
    assert!(MAX_PERMISSIONS > 0);
    assert!(MAX_CHANNEL_BINDINGS > 0);
};

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert!(DEFAULT_ALLOCATION_LIFETIME <= MAX_ALLOCATION_LIFETIME);
        assert!(CHANNEL_NUMBER_MIN < CHANNEL_NUMBER_MAX);
        assert_eq!(TRANSPORT_UDP, 17);
    }

    #[test]
    fn test_channel_number_range() {
        // Valid channel numbers
        assert!(CHANNEL_NUMBER_MIN >= 0x4000);
        assert!(CHANNEL_NUMBER_MAX <= 0x7FFF);
        
        // Ensure we have a good range
        let range = CHANNEL_NUMBER_MAX - CHANNEL_NUMBER_MIN;
        assert!(range > 1000, "should have many channel numbers available");
    }
}
