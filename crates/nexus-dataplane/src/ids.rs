//! Identifiers (note §4) and small fixed-size values carried by commands.

/// Most shards a process runs.
pub const MAX_SHARDS: usize = 64;

macro_rules! nonzero_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(u64);

        impl $name {
            /// Wraps a control-plane counter value; 0 is never a valid id.
            pub fn new(value: u64) -> Self {
                assert!(value != 0, concat!(stringify!($name), " must not be 0"));
                Self(value)
            }

            /// The raw value.
            pub fn get(self) -> u64 {
                self.0
            }
        }
    };
}

nonzero_id!(
    /// One participant transport (replaces `TransportId`). Allocated by the orchestrator.
    SessionId
);
nonzero_id!(
    /// One published track (one publish m-line). Allocated by the orchestrator.
    TrackId
);
nonzero_id!(
    /// One subscription (subscriber session, track, m-line use).
    SubscriptionId
);

/// Index of a shard in the process, `< MAX_SHARDS`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ShardId(u8);

impl ShardId {
    /// Wraps a shard index.
    pub fn new(index: u8) -> Self {
        assert!((index as usize) < MAX_SHARDS);
        Self(index)
    }

    /// The shard index.
    pub fn index(self) -> u8 {
        self.0
    }
}

/// Where a track lives: its shard and id. Phase 1: always the local shard.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrackRef {
    /// The publisher's shard.
    pub shard: ShardId,
    /// The track.
    pub track: TrackId,
}

macro_rules! short_bytes {
    ($(#[$doc:meta])* $name:ident, $cap:expr) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct $name {
            bytes: [u8; $cap],
            len: u8,
        }

        impl $name {
            /// Most bytes the value holds.
            pub const CAPACITY: usize = $cap;

            /// Copies `value`; `None` if it is empty or longer than the capacity.
            pub fn new(value: &[u8]) -> Option<Self> {
                if value.is_empty() || value.len() > $cap {
                    return None;
                }
                let mut bytes = [0u8; $cap];
                bytes[..value.len()].copy_from_slice(value);
                Some(Self { bytes, len: value.len() as u8 })
            }

            /// The value's bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.bytes[..self.len as usize]
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({:?})", stringify!($name), String::from_utf8_lossy(self.as_bytes()))
            }
        }
    };
}

short_bytes!(
    /// An m-line's `mid` (RFC 8843); 16 bytes is what the negotiator produces.
    MidValue,
    16
);
short_bytes!(
    /// An RTCP CNAME, up to the SDES item maximum of 255 bytes.
    CnameValue,
    255
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic]
    fn zero_session_id_is_refused() {
        let _ = SessionId::new(0);
    }

    #[test]
    fn short_bytes_bounds() {
        assert!(MidValue::new(b"").is_none());
        assert!(MidValue::new(&[b'a'; 17]).is_none());
        assert_eq!(MidValue::new(b"0").unwrap().as_bytes(), b"0");
        assert!(CnameValue::new(&[b'c'; 255]).is_some());
        assert!(CnameValue::new(&[b'c'; 256]).is_none());
    }
}
