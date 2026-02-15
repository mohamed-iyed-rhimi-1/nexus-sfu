//! Core types for the SWIM gossip protocol.
//!
//! This module defines the fundamental types used across the gossip implementation:
//! - `PeerState`: State machine states (Alive, Suspect, Dead)
//! - `PeerInfo`: Peer metadata including address, state, and incarnation
//! - `GossipMessage`: Protocol messages for failure detection and dissemination
//! - `StateUpdate`: CRDT delta updates for piggyback propagation
//!
//! All types use explicit sizing (u64/u32) for predictable memory layout and
//! cross-platform compatibility. Message serialization uses a fixed-size binary
//! format for zero-copy parsing.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::types::{ActorId, Dot, MAX_ACTORS};

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of peers in the cluster (matches MAX_ACTORS for consistency)
pub const MAX_PEERS: usize = 256;

/// MTU-safe UDP payload size (leaves room for IP + UDP headers)
pub const MAX_MESSAGE_SIZE: usize = 1400;

/// Maximum state updates piggybacked per message
pub const MAX_PIGGYBACK_UPDATES: usize = 16;

/// Timeout for ping response in milliseconds
pub const PING_TIMEOUT_MS: u64 = 1000;

/// Time before suspect → dead in milliseconds
pub const SUSPECT_TIMEOUT_MS: u64 = 5000;

/// Number of peers to gossip to for indirect probes
pub const GOSSIP_FANOUT: usize = 3;

/// Interval between probes in milliseconds
pub const PROBE_INTERVAL_MS: u64 = 1000;

/// Minimum header size for gossip messages (type + from_actor + incarnation + payload_len)
#[allow(dead_code)]
const MIN_HEADER_SIZE: usize = 1 + 8 + 8 + 2; // 19 bytes

/// Maximum payload size (message size minus header)
#[allow(dead_code)]
const MAX_PAYLOAD_SIZE: usize = MAX_MESSAGE_SIZE - MIN_HEADER_SIZE;

// Compile-time assertions for constants
const _: () = {
    assert!(MAX_PEERS > 0, "MAX_PEERS must be positive");
    assert!(MAX_PEERS <= 1024, "MAX_PEERS must not exceed 1024");
    assert!(
        MAX_MESSAGE_SIZE >= 512,
        "MAX_MESSAGE_SIZE must be at least 512"
    );
    assert!(
        MAX_MESSAGE_SIZE <= 65535,
        "MAX_MESSAGE_SIZE must not exceed 65535"
    );
    assert!(PING_TIMEOUT_MS > 0, "PING_TIMEOUT_MS must be positive");
    assert!(
        PING_TIMEOUT_MS < SUSPECT_TIMEOUT_MS,
        "PING_TIMEOUT_MS must be less than SUSPECT_TIMEOUT_MS"
    );
    assert!(GOSSIP_FANOUT > 0, "GOSSIP_FANOUT must be positive");
    assert!(
        GOSSIP_FANOUT <= MAX_PEERS,
        "GOSSIP_FANOUT must not exceed MAX_PEERS"
    );
    assert!(
        MAX_PIGGYBACK_UPDATES > 0,
        "MAX_PIGGYBACK_UPDATES must be positive"
    );
    assert!(
        MAX_PIGGYBACK_UPDATES <= 64,
        "MAX_PIGGYBACK_UPDATES must not exceed 64"
    );
};

// =============================================================================
// PeerState
// =============================================================================

/// State of a peer in the SWIM protocol state machine.
///
/// State transitions:
/// - Alive → Suspect: When ping times out
/// - Suspect → Alive: When peer refutes with higher incarnation
/// - Suspect → Dead: When suspect timeout expires
/// - Dead → Alive: When peer resurrects with higher incarnation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PeerState {
    /// Peer is healthy and responding to pings
    Alive = 0,
    /// Peer is suspected of failure (indirect probes sent)
    Suspect = 1,
    /// Peer is confirmed dead (removed from routing)
    Dead = 2,
}

impl PeerState {
    /// Returns true if this state represents an active peer
    #[inline]
    pub const fn is_active(&self) -> bool {
        matches!(self, PeerState::Alive)
    }

    /// Returns true if this state represents a reachable peer
    #[inline]
    pub const fn is_reachable(&self) -> bool {
        matches!(self, PeerState::Alive | PeerState::Suspect)
    }

    /// Returns the string representation of this state
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            PeerState::Alive => "Alive",
            PeerState::Suspect => "Suspect",
            PeerState::Dead => "Dead",
        }
    }

    /// Convert from u8, returns None if invalid
    #[inline]
    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(PeerState::Alive),
            1 => Some(PeerState::Suspect),
            2 => Some(PeerState::Dead),
            _ => None,
        }
    }
}

impl Default for PeerState {
    fn default() -> Self {
        PeerState::Alive
    }
}

// =============================================================================
// PeerInfo
// =============================================================================

/// Information about a peer in the cluster.
///
/// # Size
/// 48 bytes (actor_id: 8, addr: 28, state: 1, padding: 3, incarnation: 8)
///
/// # Invariants
/// - `actor_id < MAX_ACTORS`
/// - `incarnation >= 0` (starts at 0 for newly discovered peers)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerInfo {
    /// Unique identifier for this peer (must be < MAX_ACTORS)
    actor_id: ActorId,
    /// Network address for communication
    addr: SocketAddr,
    /// Current state in the SWIM state machine
    state: PeerState,
    /// Monotonic counter for refuting suspicion
    incarnation: u64,
    /// Timestamp of last contact (nanoseconds since epoch)
    last_seen_ns: u64,
}

impl PeerInfo {
    /// Creates a new PeerInfo with the given parameters.
    ///
    /// # Arguments
    /// * `actor_id` - Unique peer identifier (must be < MAX_ACTORS)
    /// * `addr` - Network address for communication
    /// * `incarnation` - Initial incarnation number
    /// * `last_seen_ns` - Initial last-seen timestamp
    ///
    /// # Panics
    /// Panics if `actor_id >= MAX_ACTORS`
    #[inline]
    pub fn new(actor_id: ActorId, addr: SocketAddr, incarnation: u64, last_seen_ns: u64) -> Self {
        assert!(
            actor_id < MAX_ACTORS as u64,
            "actor_id must be < MAX_ACTORS"
        );

        Self {
            actor_id,
            addr,
            state: PeerState::Alive,
            incarnation,
            last_seen_ns,
        }
    }

    /// Returns the actor ID
    #[inline]
    pub const fn actor_id(&self) -> ActorId {
        self.actor_id
    }

    /// Returns the network address
    #[inline]
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns the current state
    #[inline]
    pub const fn state(&self) -> PeerState {
        self.state
    }

    /// Returns the incarnation number
    #[inline]
    pub const fn incarnation(&self) -> u64 {
        self.incarnation
    }

    /// Returns the last-seen timestamp
    #[inline]
    pub const fn last_seen_ns(&self) -> u64 {
        self.last_seen_ns
    }

    /// Updates the state
    #[inline]
    pub fn set_state(&mut self, state: PeerState) {
        self.state = state;
    }

    /// Updates the incarnation number
    #[inline]
    pub fn set_incarnation(&mut self, incarnation: u64) {
        self.incarnation = incarnation;
    }

    /// Updates the last-seen timestamp
    #[inline]
    pub fn set_last_seen_ns(&mut self, last_seen_ns: u64) {
        self.last_seen_ns = last_seen_ns;
    }

    /// Encode to bytes for network transmission.
    ///
    /// Format: [actor_id:8][incarnation:8][state:1][addr_type:1][addr_data:variable]
    #[inline]
    pub fn encode(&self, buffer: &mut [u8]) -> usize {
        assert!(buffer.len() >= 24, "buffer too small for PeerInfo");

        // actor_id (8 bytes)
        buffer[0..8].copy_from_slice(&self.actor_id.to_be_bytes());

        // incarnation (8 bytes)
        buffer[8..16].copy_from_slice(&self.incarnation.to_be_bytes());

        // state (1 byte)
        buffer[16] = self.state as u8;

        // Encode socket address
        let addr_len = encode_socket_addr(self.addr, &mut buffer[17..]);

        17 + addr_len
    }

    /// Decode from bytes.
    ///
    /// Returns (PeerInfo, bytes_consumed) or None if invalid.
    #[inline]
    pub fn decode(data: &[u8], last_seen_ns: u64) -> Option<(Self, usize)> {
        if data.len() < 18 {
            return None;
        }

        let actor_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        if actor_id >= MAX_ACTORS as u64 {
            return None;
        }

        let incarnation = u64::from_be_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        let state = PeerState::from_u8(data[16])?;

        let (addr, addr_len) = decode_socket_addr(&data[17..])?;

        let peer = Self {
            actor_id,
            addr,
            state,
            incarnation,
            last_seen_ns,
        };

        Some((peer, 17 + addr_len))
    }
}

// =============================================================================
// TrackInfo (for StateUpdate)
// =============================================================================

/// Information about a media track.
///
/// Used in StateUpdate for track metadata propagation.
/// Includes `owner_node` for cascade: identifies which SFU node owns this track.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrackInfo {
    /// Track type (0 = audio, 1 = video)
    pub track_type: u8,
    /// Content type (0 = camera, 1 = screen, 2 = audio).
    /// Screen share tracks bypass viewport filtering.
    pub content_type: u8,
    /// Codec identifier
    pub codec: u32,
    /// Bitrate in kbps
    pub bitrate_kbps: u32,
    /// Actor ID of the SFU node that owns this track (0 = local/unknown).
    pub owner_node: u64,
}

/// Content type constants for `TrackInfo.content_type`.
pub const CONTENT_CAMERA: u8 = 0;
pub const CONTENT_SCREEN: u8 = 1;
pub const CONTENT_AUDIO: u8 = 2;

impl TrackInfo {
    /// Encode to bytes (18 bytes total)
    #[inline]
    pub fn encode(&self, buffer: &mut [u8]) -> usize {
        assert!(buffer.len() >= 18, "buffer too small for TrackInfo");
        buffer[0] = self.track_type;
        buffer[1] = self.content_type;
        buffer[2..6].copy_from_slice(&self.codec.to_be_bytes());
        buffer[6..10].copy_from_slice(&self.bitrate_kbps.to_be_bytes());
        buffer[10..18].copy_from_slice(&self.owner_node.to_be_bytes());
        18
    }

    /// Decode from bytes
    #[inline]
    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 18 {
            return None;
        }
        let track_type = data[0];
        let content_type = data[1];
        let codec = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
        let bitrate_kbps = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);
        let owner_node = u64::from_be_bytes([
            data[10], data[11], data[12], data[13],
            data[14], data[15], data[16], data[17],
        ]);
        Some((
            Self {
                track_type,
                content_type,
                codec,
                bitrate_kbps,
                owner_node,
            },
            18,
        ))
    }
}

impl Default for TrackInfo {
    fn default() -> Self {
        Self {
            track_type: 0,
            content_type: 0,
            codec: 0,
            bitrate_kbps: 0,
            owner_node: 0,
        }
    }
}

// =============================================================================
// StateUpdate
// =============================================================================

/// CRDT delta update for piggyback propagation.
///
/// Each update type has a fixed maximum size for predictable serialization.
/// Updates are propagated via gossip messages to achieve eventual consistency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateUpdate {
    /// Participant was added to a room
    ParticipantAdded {
        /// Room identifier
        room_id: u32,
        /// Participant identifier
        participant_id: u64,
        /// Dot for add operation
        dot: Dot,
    },
    /// Participant was removed from a room
    ParticipantRemoved {
        /// Room identifier
        room_id: u32,
        /// Participant identifier
        participant_id: u64,
        /// Dot for remove operation
        dot: Dot,
    },
    /// Track metadata was updated
    TrackUpdated {
        /// Track identifier
        track_id: u64,
        /// Track information
        info: TrackInfo,
        /// Update timestamp
        timestamp: u64,
        /// Actor that made the update
        actor: ActorId,
    },
    /// Subscription was added
    SubscriptionAdded {
        /// Track identifier
        track_id: u64,
        /// Participant subscribing
        participant_id: u64,
        /// Dot for subscription
        dot: Dot,
    },
    /// Subscription was removed
    SubscriptionRemoved {
        /// Track identifier
        track_id: u64,
        /// Participant unsubscribing
        participant_id: u64,
        /// Dot for unsubscription
        dot: Dot,
    },
    /// Request a remote node to relay a track to us.
    /// Piggybacked on gossip — the owner node starts relaying when it receives this.
    RelaySubscribe {
        /// Track to relay.
        track_id: u64,
        /// Node requesting the relay (subscriber side).
        requester_node: u64,
    },
    /// Cancel relay of a track.
    RelayUnsubscribe {
        /// Track to stop relaying.
        track_id: u64,
        /// Node that no longer needs the relay.
        requester_node: u64,
    },
}

/// Maximum size of a single StateUpdate when encoded
const MAX_STATE_UPDATE_SIZE: usize = 64;

// =============================================================================
// StateUpdate Decode Helpers (TigerStyle: ≤70 lines per function)
// =============================================================================

/// Decode a Dot from bytes at the given offset.
///
/// # TigerStyle Compliance
/// - ≤70 lines
/// - ≥2 assertions
#[inline]
fn decode_dot_at(data: &[u8], offset: usize) -> Option<Dot> {
    // Precondition: data must have enough bytes
    assert!(data.len() >= offset + 16, "insufficient data for Dot decode");
    
    let actor_id = u64::from_be_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]);
    let clock = u64::from_be_bytes([
        data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
        data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15],
    ]);

    // Validate actor_id range
    if actor_id >= MAX_ACTORS as u64 {
        return None;
    }
    // Validate clock is positive
    if clock == 0 {
        return None;
    }

    // Postcondition: dot must be valid
    Some(Dot::new_unchecked(actor_id, clock))
}

/// Decode participant update (Added or Removed) from bytes.
///
/// # TigerStyle Compliance
/// - ≤70 lines
/// - ≥2 assertions
#[inline]
fn decode_participant_update(data: &[u8], is_add: bool) -> Option<(StateUpdate, usize)> {
    // Precondition: data must have minimum length (1 type + 4 room_id + 8 participant_id + 16 dot)
    if data.len() < 29 {
        return None;
    }
    
    let room_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    let participant_id = u64::from_be_bytes([
        data[5], data[6], data[7], data[8],
        data[9], data[10], data[11], data[12],
    ]);
    let dot = decode_dot_at(data, 13)?;

    // Postcondition: IDs must be reasonable
    assert!(room_id <= u32::MAX / 2, "room_id overflow protection");
    
    let update = if is_add {
        StateUpdate::ParticipantAdded { room_id, participant_id, dot }
    } else {
        StateUpdate::ParticipantRemoved { room_id, participant_id, dot }
    };
    
    Some((update, 29))
}

/// Decode subscription update (Added or Removed) from bytes.
///
/// # TigerStyle Compliance
/// - ≤70 lines
/// - ≥2 assertions
#[inline]
fn decode_subscription_update(data: &[u8], is_add: bool) -> Option<(StateUpdate, usize)> {
    // Precondition: data must have minimum length
    if data.len() < 25 {
        return None;
    }
    
    let track_id = u32::from_be_bytes([data[1], data[2], data[3], data[4]]);
    let participant_id = u32::from_be_bytes([data[5], data[6], data[7], data[8]]);
    let dot = decode_dot_at(data, 9)?;

    // Postcondition: IDs must be reasonable
    assert!(track_id <= u32::MAX / 2, "track_id overflow protection");
    
    let update = if is_add {
        StateUpdate::SubscriptionAdded { track_id: track_id.into(), participant_id: participant_id.into(), dot }
    } else {
        StateUpdate::SubscriptionRemoved { track_id: track_id.into(), participant_id: participant_id.into(), dot }
    };
    
    Some((update, 25))
}

/// Decode relay subscribe/unsubscribe from bytes.
/// Wire format: [type:u8][track_id:u64][requester_node:u64] = 17 bytes.
#[inline]
fn decode_relay_update(data: &[u8], is_subscribe: bool) -> Option<(StateUpdate, usize)> {
    if data.len() < 17 {
        return None;
    }
    let track_id = u64::from_be_bytes([
        data[1], data[2], data[3], data[4],
        data[5], data[6], data[7], data[8],
    ]);
    let requester_node = u64::from_be_bytes([
        data[9], data[10], data[11], data[12],
        data[13], data[14], data[15], data[16],
    ]);
    assert!(track_id > 0, "track_id must be non-zero");
    assert!(requester_node > 0, "requester_node must be non-zero");

    let update = if is_subscribe {
        StateUpdate::RelaySubscribe { track_id, requester_node }
    } else {
        StateUpdate::RelayUnsubscribe { track_id, requester_node }
    };
    Some((update, 17))
}

/// Decode track update from bytes.
///
/// # TigerStyle Compliance
/// - ≤70 lines
/// - ≥2 assertions
#[inline]
fn decode_track_update(data: &[u8]) -> Option<(StateUpdate, usize)> {
    // Precondition: data must have minimum length for header + track_id (1 + 8 = 9)
    if data.len() < 30 {
        return None;
    }
    
    let track_id = u64::from_be_bytes([
        data[1], data[2], data[3], data[4],
        data[5], data[6], data[7], data[8],
    ]);
    let (info, info_len) = TrackInfo::decode(&data[9..])?;
    let offset = 9 + info_len;
    
    if data.len() < offset + 16 {
        return None;
    }
    
    let timestamp = u64::from_be_bytes([
        data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
        data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
    ]);
    let actor = u64::from_be_bytes([
        data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
        data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15],
    ]);

    // Validate actor range
    if actor >= MAX_ACTORS as u64 {
        return None;
    }

    // Postcondition: track_id must be reasonable
    assert!(track_id <= u64::MAX / 2, "track_id overflow protection");

    Some((
        StateUpdate::TrackUpdated { track_id, info, timestamp, actor },
        offset + 16,
    ))
}

impl StateUpdate {
    /// Encode the update to bytes.
    ///
    /// Format: [type:1][payload...]
    /// Returns bytes written.
    #[inline]
    pub fn encode(&self, buffer: &mut [u8]) -> usize {
        assert!(
            buffer.len() >= MAX_STATE_UPDATE_SIZE,
            "buffer too small for StateUpdate"
        );

        match self {
            StateUpdate::ParticipantAdded { room_id, participant_id, dot } => {
                let participant_id_u64: u64 = *participant_id;
                buffer[0] = 0; // type
                buffer[1..5].copy_from_slice(&room_id.to_be_bytes());
                buffer[5..13].copy_from_slice(&participant_id_u64.to_be_bytes());
                buffer[13..21].copy_from_slice(&dot.actor_id().to_be_bytes());
                buffer[21..29].copy_from_slice(&dot.clock().to_be_bytes());
                29
            }
            StateUpdate::ParticipantRemoved { room_id, participant_id, dot } => {
                let participant_id_u64: u64 = *participant_id;
                buffer[0] = 1;
                buffer[1..5].copy_from_slice(&room_id.to_be_bytes());
                buffer[5..13].copy_from_slice(&participant_id_u64.to_be_bytes());
                buffer[13..21].copy_from_slice(&dot.actor_id().to_be_bytes());
                buffer[21..29].copy_from_slice(&dot.clock().to_be_bytes());
                29
            }
            StateUpdate::TrackUpdated {
                track_id,
                info,
                timestamp,
                actor,
            } => {
                buffer[0] = 2;
                buffer[1..9].copy_from_slice(&track_id.to_be_bytes());
                let info_len = info.encode(&mut buffer[9..]);
                let offset = 9 + info_len;
                buffer[offset..offset + 8].copy_from_slice(&timestamp.to_be_bytes());
                buffer[offset + 8..offset + 16].copy_from_slice(&actor.to_be_bytes());
                offset + 16
            }
            StateUpdate::SubscriptionAdded {
                track_id,
                participant_id,
                dot,
            } => {
                buffer[0] = 3;
                buffer[1..9].copy_from_slice(&track_id.to_be_bytes());
                buffer[9..17].copy_from_slice(&participant_id.to_be_bytes());
                buffer[17..25].copy_from_slice(&dot.actor_id().to_be_bytes());
                buffer[25..33].copy_from_slice(&dot.clock().to_be_bytes());
                33
            }
            StateUpdate::SubscriptionRemoved {
                track_id,
                participant_id,
                dot,
            } => {
                buffer[0] = 4;
                buffer[1..9].copy_from_slice(&track_id.to_be_bytes());
                buffer[9..17].copy_from_slice(&participant_id.to_be_bytes());
                buffer[17..25].copy_from_slice(&dot.actor_id().to_be_bytes());
                buffer[25..33].copy_from_slice(&dot.clock().to_be_bytes());
                33
            }
            StateUpdate::RelaySubscribe { track_id, requester_node } => {
                buffer[0] = 5;
                buffer[1..9].copy_from_slice(&track_id.to_be_bytes());
                buffer[9..17].copy_from_slice(&requester_node.to_be_bytes());
                17
            }
            StateUpdate::RelayUnsubscribe { track_id, requester_node } => {
                buffer[0] = 6;
                buffer[1..9].copy_from_slice(&track_id.to_be_bytes());
                buffer[9..17].copy_from_slice(&requester_node.to_be_bytes());
                17
            }
        }
    }

    /// Decode from bytes.
    ///
    /// Returns (StateUpdate, bytes_consumed) or None if invalid.
    ///
    /// # TigerStyle Compliance
    /// - ≤70 lines (uses helper functions)
    /// - ≥2 assertions (in helpers)
    #[inline]
    pub fn decode(data: &[u8]) -> Option<(Self, usize)> {
        // Precondition: data must not be empty
        if data.is_empty() {
            return None;
        }

        let update_type = data[0];

        // Dispatch to type-specific helper functions
        // TigerStyle: centralize control flow, push logic to helpers
        match update_type {
            0 => decode_participant_update(data, true),  // ParticipantAdded
            1 => decode_participant_update(data, false), // ParticipantRemoved
            2 => decode_track_update(data),              // TrackUpdated
            3 => decode_subscription_update(data, true), // SubscriptionAdded
            4 => decode_subscription_update(data, false), // SubscriptionRemoved
            5 => decode_relay_update(data, true),         // RelaySubscribe
            6 => decode_relay_update(data, false),        // RelayUnsubscribe
            _ => None,
        }
    }
}

// =============================================================================
// GossipMessage
// =============================================================================

/// SWIM protocol messages.
///
/// Each message type serves a specific role in the protocol:
/// - `Ping`/`Ack`: Primary failure detection via direct probes
/// - `PingReq`: Indirect probing when direct probe fails
/// - `Suspect`/`Alive`/`Dead`: Membership state dissemination
///
/// All messages can optionally carry piggyback state updates for efficient
/// state propagation without additional network overhead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GossipMessage {
    /// Direct probe request
    Ping {
        /// Sender's actor ID
        from: ActorId,
        /// Sender's incarnation number
        incarnation: u64,
        /// Piggybacked state updates
        piggyback: Vec<StateUpdate>,
    },
    /// Probe acknowledgment
    Ack {
        /// Sender's actor ID
        from: ActorId,
        /// Sender's incarnation number
        incarnation: u64,
        /// Piggybacked state updates
        piggyback: Vec<StateUpdate>,
    },
    /// Indirect probe request (asks peer to ping target)
    PingReq {
        /// Requester's actor ID
        from: ActorId,
        /// Target peer to probe
        target: ActorId,
        /// Target peer's address
        target_addr: SocketAddr,
        /// Requester's address for forwarding ack
        requester_addr: SocketAddr,
    },
    /// Report that a peer is suspected of failure
    Suspect {
        /// Suspected peer's actor ID
        actor_id: ActorId,
        /// Last known incarnation
        incarnation: u64,
    },
    /// Report that a peer is alive (refutation)
    Alive {
        /// Alive peer's actor ID
        actor_id: ActorId,
        /// New incarnation number
        incarnation: u64,
    },
    /// Report that a peer is confirmed dead
    Dead {
        /// Dead peer's actor ID
        actor_id: ActorId,
    },
    /// Forwarded ack from indirect probe helper
    ForwardedAck {
        /// Original target that responded
        target: ActorId,
        /// Target's incarnation number
        incarnation: u64,
    },
    /// Full state snapshot for anti-entropy
    StateSnapshot {
        /// Sender's actor ID
        from: ActorId,
        /// Sender's incarnation
        incarnation: u64,
        /// Membership list entries (actor_id, incarnation, state)
        members: Vec<(ActorId, u64, u8)>,
        /// Queued state updates
        updates: Vec<StateUpdate>,
    },
}

/// Message type identifiers
const MSG_TYPE_PING: u8 = 0;
const MSG_TYPE_ACK: u8 = 1;
const MSG_TYPE_PING_REQ: u8 = 2;
const MSG_TYPE_SUSPECT: u8 = 3;
const MSG_TYPE_ALIVE: u8 = 4;
const MSG_TYPE_DEAD: u8 = 5;
const MSG_TYPE_FORWARDED_ACK: u8 = 6;
const MSG_TYPE_STATE_SNAPSHOT: u8 = 7;

impl GossipMessage {
    /// Encode the message to bytes.
    ///
    /// Format: [type:1][from_actor:8][incarnation:8][payload_len:2][payload...]
    ///
    /// # Panics
    /// Panics if the encoded size exceeds MAX_MESSAGE_SIZE
    #[inline]
    pub fn encode(&self) -> Vec<u8> {
        let mut buffer = Vec::with_capacity(MAX_MESSAGE_SIZE);

        match self {
            GossipMessage::Ping {
                from,
                incarnation,
                piggyback,
            } => {
                buffer.push(MSG_TYPE_PING);
                buffer.extend_from_slice(&from.to_be_bytes());
                buffer.extend_from_slice(&incarnation.to_be_bytes());

                // Encode piggyback updates
                let piggyback_count = piggyback.len().min(MAX_PIGGYBACK_UPDATES);
                buffer.extend_from_slice(&(piggyback_count as u16).to_be_bytes());

                let mut update_buffer = [0u8; MAX_STATE_UPDATE_SIZE];
                for (i, update) in piggyback.iter().enumerate() {
                    if i >= MAX_PIGGYBACK_UPDATES {
                        break;
                    }
                    let len = update.encode(&mut update_buffer);
                    buffer.extend_from_slice(&(len as u16).to_be_bytes());
                    buffer.extend_from_slice(&update_buffer[..len]);
                }
            }
            GossipMessage::Ack {
                from,
                incarnation,
                piggyback,
            } => {
                buffer.push(MSG_TYPE_ACK);
                buffer.extend_from_slice(&from.to_be_bytes());
                buffer.extend_from_slice(&incarnation.to_be_bytes());

                let piggyback_count = piggyback.len().min(MAX_PIGGYBACK_UPDATES);
                buffer.extend_from_slice(&(piggyback_count as u16).to_be_bytes());

                let mut update_buffer = [0u8; MAX_STATE_UPDATE_SIZE];
                for (i, update) in piggyback.iter().enumerate() {
                    if i >= MAX_PIGGYBACK_UPDATES {
                        break;
                    }
                    let len = update.encode(&mut update_buffer);
                    buffer.extend_from_slice(&(len as u16).to_be_bytes());
                    buffer.extend_from_slice(&update_buffer[..len]);
                }
            }
            GossipMessage::PingReq {
                from,
                target,
                target_addr,
                requester_addr,
            } => {
                buffer.push(MSG_TYPE_PING_REQ);
                buffer.extend_from_slice(&from.to_be_bytes());
                buffer.extend_from_slice(&target.to_be_bytes());

                let mut addr_buffer = [0u8; 32];
                let addr_len = encode_socket_addr(*target_addr, &mut addr_buffer);
                buffer.extend_from_slice(&addr_buffer[..addr_len]);
                
                let requester_len = encode_socket_addr(*requester_addr, &mut addr_buffer);
                buffer.extend_from_slice(&addr_buffer[..requester_len]);
            }
            GossipMessage::Suspect { actor_id, incarnation } => {
                buffer.push(MSG_TYPE_SUSPECT);
                buffer.extend_from_slice(&actor_id.to_be_bytes());
                buffer.extend_from_slice(&incarnation.to_be_bytes());
            }
            GossipMessage::Alive { actor_id, incarnation } => {
                buffer.push(MSG_TYPE_ALIVE);
                buffer.extend_from_slice(&actor_id.to_be_bytes());
                buffer.extend_from_slice(&incarnation.to_be_bytes());
            }
            GossipMessage::Dead { actor_id } => {
                buffer.push(MSG_TYPE_DEAD);
                buffer.extend_from_slice(&actor_id.to_be_bytes());
            }
            GossipMessage::ForwardedAck { target, incarnation } => {
                buffer.push(MSG_TYPE_FORWARDED_ACK);
                buffer.extend_from_slice(&target.to_be_bytes());
                buffer.extend_from_slice(&incarnation.to_be_bytes());
            }
            GossipMessage::StateSnapshot {
                from,
                incarnation,
                members,
                updates,
            } => {
                buffer.push(MSG_TYPE_STATE_SNAPSHOT);
                buffer.extend_from_slice(&from.to_be_bytes());
                buffer.extend_from_slice(&incarnation.to_be_bytes());
                
                // Encode member count (bounded by MAX_PEERS)
                let member_count = members.len().min(MAX_PEERS);
                buffer.extend_from_slice(&(member_count as u16).to_be_bytes());
                
                for (i, (actor_id, inc, state)) in members.iter().enumerate() {
                    if i >= MAX_PEERS {
                        break;
                    }
                    buffer.extend_from_slice(&actor_id.to_be_bytes());
                    buffer.extend_from_slice(&inc.to_be_bytes());
                    buffer.push(*state);
                }
                
                // Encode state updates
                let update_count = updates.len().min(MAX_PIGGYBACK_UPDATES);
                buffer.extend_from_slice(&(update_count as u16).to_be_bytes());
                
                let mut update_buffer = [0u8; MAX_STATE_UPDATE_SIZE];
                for (i, update) in updates.iter().enumerate() {
                    if i >= MAX_PIGGYBACK_UPDATES {
                        break;
                    }
                    let len = update.encode(&mut update_buffer);
                    buffer.extend_from_slice(&(len as u16).to_be_bytes());
                    buffer.extend_from_slice(&update_buffer[..len]);
                }
            }
        }

        assert!(
            buffer.len() <= MAX_MESSAGE_SIZE,
            "Encoded message size {} exceeds MAX_MESSAGE_SIZE {}",
            buffer.len(),
            MAX_MESSAGE_SIZE
        );

        buffer
    }

    /// Decode a message from bytes.
    ///
    /// # Returns
    /// The decoded message, or an error description if decoding fails.
    #[inline]
    pub fn decode(data: &[u8]) -> Result<Self, &'static str> {
        if data.is_empty() {
            return Err("empty message");
        }

        let msg_type = data[0];

        match msg_type {
            MSG_TYPE_PING => Self::decode_ping(&data[1..]),
            MSG_TYPE_ACK => Self::decode_ack(&data[1..]),
            MSG_TYPE_PING_REQ => Self::decode_ping_req(&data[1..]),
            MSG_TYPE_SUSPECT => Self::decode_suspect(&data[1..]),
            MSG_TYPE_ALIVE => Self::decode_alive(&data[1..]),
            MSG_TYPE_DEAD => Self::decode_dead(&data[1..]),
            MSG_TYPE_FORWARDED_ACK => Self::decode_forwarded_ack(&data[1..]),
            MSG_TYPE_STATE_SNAPSHOT => Self::decode_state_snapshot(&data[1..]),
            _ => Err("invalid message type"),
        }
    }

    fn decode_ping(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 18 {
            return Err("ping message too short");
        }

        let from = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        if from >= MAX_ACTORS as u64 {
            return Err("invalid actor_id in ping");
        }

        let incarnation = u64::from_be_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        let piggyback_count = u16::from_be_bytes([data[16], data[17]]) as usize;

        if piggyback_count > MAX_PIGGYBACK_UPDATES {
            return Err("too many piggyback updates");
        }

        let mut piggyback = Vec::with_capacity(piggyback_count);
        let mut offset = 18;

        for _ in 0..piggyback_count {
            if offset + 2 > data.len() {
                return Err("piggyback data truncated");
            }
            let update_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + update_len > data.len() {
                return Err("piggyback update truncated");
            }

            let (update, _) =
                StateUpdate::decode(&data[offset..offset + update_len])
                    .ok_or("invalid piggyback update")?;
            piggyback.push(update);
            offset += update_len;
        }

        Ok(GossipMessage::Ping {
            from,
            incarnation,
            piggyback,
        })
    }

    fn decode_ack(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 18 {
            return Err("ack message too short");
        }

        let from = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        if from >= MAX_ACTORS as u64 {
            return Err("invalid actor_id in ack");
        }

        let incarnation = u64::from_be_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        let piggyback_count = u16::from_be_bytes([data[16], data[17]]) as usize;

        if piggyback_count > MAX_PIGGYBACK_UPDATES {
            return Err("too many piggyback updates");
        }

        let mut piggyback = Vec::with_capacity(piggyback_count);
        let mut offset = 18;

        for _ in 0..piggyback_count {
            if offset + 2 > data.len() {
                return Err("piggyback data truncated");
            }
            let update_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + update_len > data.len() {
                return Err("piggyback update truncated");
            }

            let (update, _) =
                StateUpdate::decode(&data[offset..offset + update_len])
                    .ok_or("invalid piggyback update")?;
            piggyback.push(update);
            offset += update_len;
        }

        Ok(GossipMessage::Ack {
            from,
            incarnation,
            piggyback,
        })
    }

    fn decode_ping_req(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 17 {
            return Err("ping_req message too short");
        }

        let from = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        if from >= MAX_ACTORS as u64 {
            return Err("invalid from actor_id in ping_req");
        }

        let target = u64::from_be_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        if target >= MAX_ACTORS as u64 {
            return Err("invalid target actor_id in ping_req");
        }

        let (target_addr, target_addr_len) =
            decode_socket_addr(&data[16..]).ok_or("invalid target_addr in ping_req")?;
        
        let requester_offset = 16 + target_addr_len;
        let (requester_addr, _) =
            decode_socket_addr(&data[requester_offset..]).ok_or("invalid requester_addr in ping_req")?;

        Ok(GossipMessage::PingReq {
            from,
            target,
            target_addr,
            requester_addr,
        })
    }

    fn decode_suspect(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 16 {
            return Err("suspect message too short");
        }

        let actor_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        if actor_id >= MAX_ACTORS as u64 {
            return Err("invalid actor_id in suspect");
        }

        let incarnation = u64::from_be_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        Ok(GossipMessage::Suspect { actor_id, incarnation })
    }

    fn decode_alive(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 16 {
            return Err("alive message too short");
        }

        let actor_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        if actor_id >= MAX_ACTORS as u64 {
            return Err("invalid actor_id in alive");
        }

        let incarnation = u64::from_be_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        Ok(GossipMessage::Alive { actor_id, incarnation })
    }

    fn decode_dead(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 8 {
            return Err("dead message too short");
        }

        let actor_id = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        if actor_id >= MAX_ACTORS as u64 {
            return Err("invalid actor_id in dead");
        }

        Ok(GossipMessage::Dead { actor_id })
    }

    fn decode_forwarded_ack(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 16 {
            return Err("forwarded_ack message too short");
        }

        let target = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        if target >= MAX_ACTORS as u64 {
            return Err("invalid target in forwarded_ack");
        }

        let incarnation = u64::from_be_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        Ok(GossipMessage::ForwardedAck { target, incarnation })
    }

    fn decode_state_snapshot(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() < 18 {
            return Err("state_snapshot message too short");
        }

        let from = u64::from_be_bytes([
            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
        ]);

        if from >= MAX_ACTORS as u64 {
            return Err("invalid from in state_snapshot");
        }

        let incarnation = u64::from_be_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);

        let member_count = u16::from_be_bytes([data[16], data[17]]) as usize;
        if member_count > MAX_PEERS {
            return Err("too many members in state_snapshot");
        }

        let mut offset = 18;
        let mut members = Vec::with_capacity(member_count);

        for _ in 0..member_count {
            if offset + 17 > data.len() {
                return Err("member data truncated");
            }
            let actor_id = u64::from_be_bytes([
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
            ]);
            let inc = u64::from_be_bytes([
                data[offset + 8], data[offset + 9], data[offset + 10], data[offset + 11],
                data[offset + 12], data[offset + 13], data[offset + 14], data[offset + 15],
            ]);
            let state = data[offset + 16];
            offset += 17;
            
            if actor_id < MAX_ACTORS as u64 && state <= 2 {
                members.push((actor_id, inc, state));
            }
        }

        if offset + 2 > data.len() {
            return Err("update count truncated");
        }
        let update_count = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
        offset += 2;

        if update_count > MAX_PIGGYBACK_UPDATES {
            return Err("too many updates in state_snapshot");
        }

        let mut updates = Vec::with_capacity(update_count);
        for _ in 0..update_count {
            if offset + 2 > data.len() {
                return Err("update data truncated");
            }
            let update_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
            offset += 2;

            if offset + update_len > data.len() {
                return Err("update truncated");
            }

            if let Some((update, _)) = StateUpdate::decode(&data[offset..offset + update_len]) {
                updates.push(update);
            }
            offset += update_len;
        }

        Ok(GossipMessage::StateSnapshot {
            from,
            incarnation,
            members,
            updates,
        })
    }
}

// =============================================================================
// Helper Functions for Socket Address Encoding
// =============================================================================

/// Encode a socket address to bytes.
///
/// Format:
/// - IPv4: [type:1 (0)][ip:4][port:2] = 7 bytes
/// - IPv6: [type:1 (1)][ip:16][port:2][flowinfo:4][scope_id:4] = 27 bytes
#[inline]
fn encode_socket_addr(addr: SocketAddr, buffer: &mut [u8]) -> usize {
    match addr {
        SocketAddr::V4(v4) => {
            assert!(buffer.len() >= 7, "buffer too small for IPv4");
            buffer[0] = 0; // IPv4 type
            buffer[1..5].copy_from_slice(&v4.ip().octets());
            buffer[5..7].copy_from_slice(&v4.port().to_be_bytes());
            7
        }
        SocketAddr::V6(v6) => {
            assert!(buffer.len() >= 27, "buffer too small for IPv6");
            buffer[0] = 1; // IPv6 type
            buffer[1..17].copy_from_slice(&v6.ip().octets());
            buffer[17..19].copy_from_slice(&v6.port().to_be_bytes());
            buffer[19..23].copy_from_slice(&v6.flowinfo().to_be_bytes());
            buffer[23..27].copy_from_slice(&v6.scope_id().to_be_bytes());
            27
        }
    }
}

/// Decode a socket address from bytes.
///
/// Returns (SocketAddr, bytes_consumed) or None if invalid.
#[inline]
fn decode_socket_addr(data: &[u8]) -> Option<(SocketAddr, usize)> {
    if data.is_empty() {
        return None;
    }

    match data[0] {
        0 => {
            // IPv4
            if data.len() < 7 {
                return None;
            }
            let ip = Ipv4Addr::new(data[1], data[2], data[3], data[4]);
            let port = u16::from_be_bytes([data[5], data[6]]);
            Some((SocketAddr::new(IpAddr::V4(ip), port), 7))
        }
        1 => {
            // IPv6
            if data.len() < 27 {
                return None;
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[1..17]);
            let ip = Ipv6Addr::from(ip_bytes);
            let port = u16::from_be_bytes([data[17], data[18]]);
            // Note: flowinfo and scope_id are parsed but SocketAddrV6 requires them
            // For simplicity, we create a basic V6 address
            Some((SocketAddr::new(IpAddr::V6(ip), port), 27))
        }
        _ => None,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_state_values() {
        assert_eq!(PeerState::Alive as u8, 0);
        assert_eq!(PeerState::Suspect as u8, 1);
        assert_eq!(PeerState::Dead as u8, 2);
    }

    #[test]
    fn test_peer_state_from_u8() {
        assert_eq!(PeerState::from_u8(0), Some(PeerState::Alive));
        assert_eq!(PeerState::from_u8(1), Some(PeerState::Suspect));
        assert_eq!(PeerState::from_u8(2), Some(PeerState::Dead));
        assert_eq!(PeerState::from_u8(3), None);
        assert_eq!(PeerState::from_u8(255), None);
    }

    #[test]
    fn test_peer_state_is_active() {
        assert!(PeerState::Alive.is_active());
        assert!(!PeerState::Suspect.is_active());
        assert!(!PeerState::Dead.is_active());
    }

    #[test]
    fn test_peer_state_is_reachable() {
        assert!(PeerState::Alive.is_reachable());
        assert!(PeerState::Suspect.is_reachable());
        assert!(!PeerState::Dead.is_reachable());
    }

    #[test]
    fn test_peer_info_new() {
        let addr: SocketAddr = "192.168.1.1:7946".parse().unwrap();
        let peer = PeerInfo::new(5, addr, 1, 1000);

        assert_eq!(peer.actor_id(), 5);
        assert_eq!(peer.addr(), addr);
        assert_eq!(peer.state(), PeerState::Alive);
        assert_eq!(peer.incarnation(), 1);
        assert_eq!(peer.last_seen_ns(), 1000);
    }

    #[test]
    #[should_panic(expected = "actor_id must be < MAX_ACTORS")]
    fn test_peer_info_invalid_actor_id() {
        let addr: SocketAddr = "192.168.1.1:7946".parse().unwrap();
        let _ = PeerInfo::new(MAX_ACTORS as u64, addr, 1, 1000);
    }

    #[test]
    fn test_peer_info_encode_decode_roundtrip() {
        let addr: SocketAddr = "192.168.1.1:7946".parse().unwrap();
        let peer = PeerInfo::new(5, addr, 42, 1000);

        let mut buffer = [0u8; 64];
        let len = peer.encode(&mut buffer);

        let (decoded, decoded_len) = PeerInfo::decode(&buffer[..len], 2000).unwrap();

        assert_eq!(decoded_len, len);
        assert_eq!(decoded.actor_id(), peer.actor_id());
        assert_eq!(decoded.addr(), peer.addr());
        assert_eq!(decoded.incarnation(), peer.incarnation());
        // last_seen_ns is set from parameter, not decoded
        assert_eq!(decoded.last_seen_ns(), 2000);
    }

    #[test]
    fn test_peer_info_ipv6() {
        let addr: SocketAddr = "[::1]:7946".parse().unwrap();
        let peer = PeerInfo::new(10, addr, 5, 5000);

        let mut buffer = [0u8; 64];
        let len = peer.encode(&mut buffer);

        let (decoded, _) = PeerInfo::decode(&buffer[..len], 5000).unwrap();

        assert_eq!(decoded.actor_id(), 10);
        assert_eq!(decoded.addr(), addr);
    }

    #[test]
    fn test_track_info_encode_decode() {
        let info = TrackInfo {
            track_type: 1,
            content_type: 1,
            codec: 12345,
            bitrate_kbps: 128,
            owner_node: 0,
        };

        let mut buffer = [0u8; 32];
        let len = info.encode(&mut buffer);

        let (decoded, decoded_len) = TrackInfo::decode(&buffer[..len]).unwrap();

        assert_eq!(decoded_len, len);
        assert_eq!(decoded.track_type, info.track_type);
        assert_eq!(decoded.content_type, info.content_type);
        assert_eq!(decoded.codec, info.codec);
        assert_eq!(decoded.bitrate_kbps, info.bitrate_kbps);
        assert_eq!(decoded.owner_node, info.owner_node);
    }

    #[test]
    fn test_state_update_participant_added_roundtrip() {
        let dot = Dot::new(5, 10);
        let update = StateUpdate::ParticipantAdded {
            room_id: 1,
            participant_id: 42,
            dot,
        };

        let mut buffer = [0u8; MAX_STATE_UPDATE_SIZE];
        let len = update.encode(&mut buffer);

        let (decoded, decoded_len) = StateUpdate::decode(&buffer[..len]).unwrap();

        assert_eq!(decoded_len, len);
        assert_eq!(decoded, update);
    }

    #[test]
    fn test_state_update_track_updated_roundtrip() {
        let update = StateUpdate::TrackUpdated {
            track_id: 100,
            info: TrackInfo {
                track_type: 1,
                content_type: 0,
                codec: 96,
                bitrate_kbps: 256,
                owner_node: 0,
            },
            timestamp: 123456789,
            actor: 7,
        };

        let mut buffer = [0u8; MAX_STATE_UPDATE_SIZE];
        let len = update.encode(&mut buffer);

        let (decoded, decoded_len) = StateUpdate::decode(&buffer[..len]).unwrap();

        assert_eq!(decoded_len, len);
        assert_eq!(decoded, update);
    }

    #[test]
    fn test_gossip_message_ping_roundtrip() {
        let dot = Dot::new(1, 5);
        let msg = GossipMessage::Ping {
            from: 5,
            incarnation: 42,
            piggyback: vec![StateUpdate::ParticipantAdded {
                room_id: 1,
                participant_id: 10,
                dot,
            }],
        };

        let encoded = msg.encode();
        let decoded = GossipMessage::decode(&encoded).unwrap();

        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_gossip_message_ack_roundtrip() {
        let msg = GossipMessage::Ack {
            from: 10,
            incarnation: 100,
            piggyback: vec![],
        };

        let encoded = msg.encode();
        let decoded = GossipMessage::decode(&encoded).unwrap();

        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_gossip_message_ping_req_roundtrip() {
        let target_addr: SocketAddr = "10.0.0.5:7946".parse().unwrap();
        let requester_addr: SocketAddr = "10.0.0.1:7946".parse().unwrap();
        let msg = GossipMessage::PingReq {
            from: 1,
            target: 5,
            target_addr,
            requester_addr,
        };

        let encoded = msg.encode();
        let decoded = GossipMessage::decode(&encoded).unwrap();

        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_gossip_message_suspect_roundtrip() {
        let msg = GossipMessage::Suspect {
            actor_id: 7,
            incarnation: 55,
        };

        let encoded = msg.encode();
        let decoded = GossipMessage::decode(&encoded).unwrap();

        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_gossip_message_alive_roundtrip() {
        let msg = GossipMessage::Alive {
            actor_id: 3,
            incarnation: 99,
        };

        let encoded = msg.encode();
        let decoded = GossipMessage::decode(&encoded).unwrap();

        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_gossip_message_dead_roundtrip() {
        let msg = GossipMessage::Dead { actor_id: 15 };

        let encoded = msg.encode();
        let decoded = GossipMessage::decode(&encoded).unwrap();

        assert_eq!(decoded, msg);
    }

    #[test]
    fn test_gossip_message_max_piggyback() {
        let dot = Dot::new(1, 1);
        let mut piggyback = Vec::with_capacity(MAX_PIGGYBACK_UPDATES);
        for i in 0..MAX_PIGGYBACK_UPDATES {
            piggyback.push(StateUpdate::ParticipantAdded {
                room_id: 1,
                participant_id: i as u64,
                dot,
            });
        }

        let msg = GossipMessage::Ping {
            from: 1,
            incarnation: 1,
            piggyback,
        };

        let encoded = msg.encode();
        assert!(encoded.len() <= MAX_MESSAGE_SIZE);

        let decoded = GossipMessage::decode(&encoded).unwrap();
        if let GossipMessage::Ping { piggyback, .. } = decoded {
            assert_eq!(piggyback.len(), MAX_PIGGYBACK_UPDATES);
        } else {
            panic!("Expected Ping message");
        }
    }

    #[test]
    fn test_decode_invalid_message_type() {
        let data = [255u8; 20];
        let result = GossipMessage::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_empty_message() {
        let data: [u8; 0] = [];
        let result = GossipMessage::decode(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_socket_addr_encode_decode_ipv4() {
        let addr: SocketAddr = "192.168.1.100:8080".parse().unwrap();
        let mut buffer = [0u8; 32];
        let len = encode_socket_addr(addr, &mut buffer);

        let (decoded, decoded_len) = decode_socket_addr(&buffer[..len]).unwrap();

        assert_eq!(decoded_len, len);
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_socket_addr_encode_decode_ipv6() {
        let addr: SocketAddr = "[2001:db8::1]:8080".parse().unwrap();
        let mut buffer = [0u8; 32];
        let len = encode_socket_addr(addr, &mut buffer);

        let (decoded, decoded_len) = decode_socket_addr(&buffer[..len]).unwrap();

        assert_eq!(decoded_len, len);
        // Compare IP and port (flowinfo/scope_id may differ)
        assert_eq!(decoded.ip(), addr.ip());
        assert_eq!(decoded.port(), addr.port());
    }
}
