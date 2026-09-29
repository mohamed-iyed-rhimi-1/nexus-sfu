//! RoomManager: room CRUD, participant join/leave, notifications.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::signal::SignalMessage;
use nexus_state::DistributedState;

use super::ParticipantHandle;

/// Most rooms the orchestrator holds.
pub const MAX_ROOMS: usize = 10_000;
const MAX_PARTICIPANTS_PER_ROOM: u32 = 1_000;
/// Longest participant name accepted in `Join` (it is copied to every peer).
pub const MAX_PARTICIPANT_NAME_LEN: usize = 256;
/// Rooms one connection may have created and not yet released.
pub const MAX_ROOMS_PER_CREATOR: usize = 4;

pub struct RoomManager {
    room_names: HashMap<String, u32>,
    distributed_state: Arc<DistributedState>,
    /// Rooms each participant created. A room still empty when its creator
    /// leaves or disconnects is released; a joined room is released by its last
    /// member leaving. So no room outlives both its creator and its members.
    created: HashMap<u64, Vec<u32>>,
}

/// The reply to a `Create` or `Join` for a room the token does not name.
const FORBIDDEN_MESSAGE: &str = "Token does not grant this room";

/// Whether the participant's token grants the room with this name (`None`: a new
/// unnamed room). Unknown participants are granted nothing.
fn granted(
    sessions: &HashMap<u64, ParticipantHandle>,
    participant_id: u64,
    name: Option<&str>,
) -> bool {
    sessions
        .get(&participant_id)
        .is_some_and(|handle| handle.grant.allows(name))
}

impl RoomManager {
    pub fn new(distributed_state: Arc<DistributedState>) -> Self {
        Self {
            room_names: HashMap::with_capacity(256),
            distributed_state,
            created: HashMap::new(),
        }
    }

    pub fn handle_create(
        &mut self,
        participant_id: u64,
        room_name: Option<String>,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        if participant_id == 0 {
            return;
        }
        // Before the name lookup: only tokens that name a room reach it (Phase 1.9a)
        if !granted(sessions, participant_id, room_name.as_deref()) {
            send_error(sessions, participant_id, "FORBIDDEN", FORBIDDEN_MESSAGE);
            return;
        }

        // Idempotent: return existing room if name matches
        if let Some(ref name) = room_name {
            if let Some(&existing_id) = self.room_names.get(name) {
                send_to(
                    sessions,
                    participant_id,
                    SignalMessage::Created {
                        room_id: existing_id as u64,
                        room_name: Some(name.clone()),
                    },
                );
                return;
            }
        }

        let Some(room_id) = self.new_room(participant_id, room_name.as_deref(), sessions) else {
            return;
        };
        if let Some(ref name) = room_name {
            self.room_names.insert(name.clone(), room_id);
        }

        send_to(
            sessions,
            participant_id,
            SignalMessage::Created {
                room_id: room_id as u64,
                room_name,
            },
        );

        info!("Room {} created by participant {}", room_id, participant_id);
    }

    /// Creates a room in the shared state and returns its id, or sends the error.
    /// Network input: the name's length and the id counter are checked here, not
    /// asserted downstream (exit criterion 6).
    fn new_room(
        &mut self,
        participant_id: u64,
        name: Option<&str>,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) -> Option<u32> {
        if name.is_some_and(|n| n.len() > nexus_state::MAX_ROOM_NAME_LEN) {
            let message = format!(
                "Room name longer than {} bytes",
                nexus_state::MAX_ROOM_NAME_LEN
            );
            send_error(sessions, participant_id, "INVALID_INPUT", &message);
            return None;
        }
        // Every room counts, named or not, however it was created (REST too)
        if self.distributed_state.room_count() >= MAX_ROOMS {
            send_error(
                sessions,
                participant_id,
                "ROOM_LIMIT",
                "Maximum rooms reached",
            );
            return None;
        }
        let state = &self.distributed_state;
        let mine = self.created.entry(participant_id).or_default();
        mine.retain(|&room| state.room_exists(room));
        if mine.len() >= MAX_ROOMS_PER_CREATOR {
            let message = format!("At most {MAX_ROOMS_PER_CREATOR} rooms created per connection");
            send_error(sessions, participant_id, "ROOM_LIMIT", &message);
            return None;
        }
        let room_id = match self.allocate_room(name) {
            Ok(id) => id,
            Err(reason) => {
                send_error(sessions, participant_id, "ROOM_LIMIT", reason);
                return None;
            }
        };
        let mine = self.created.entry(participant_id).or_default();
        assert!(mine.len() < MAX_ROOMS_PER_CREATOR);
        mine.push(room_id);
        debug_assert!(room_id != 0);
        Some(room_id)
    }

    /// Creates the room under the next free id of the shared allocator
    /// (`DistributedState::create_room_auto`, also used by the REST API).
    fn allocate_room(&mut self, name: Option<&str>) -> Result<u32, &'static str> {
        let name = name.unwrap_or_default().to_string();
        match self
            .distributed_state
            .create_room_auto(name, MAX_PARTICIPANTS_PER_ROOM)
        {
            Ok(room_id) => {
                assert!(room_id != 0);
                Ok(room_id)
            }
            Err(nexus_state::CrdtError::Overflow) => Err("Room ids exhausted"),
            Err(e) => {
                warn!("Failed to create room in CRDT: {:?}", e);
                Err("Room not created")
            }
        }
    }

    /// Whether the room exists and the participant's token names it; sends
    /// `ROOM_NOT_FOUND` or `FORBIDDEN` if not.
    fn room_granted(
        &self,
        participant_id: u64,
        room_id: u32,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) -> bool {
        let Some(room) = self.distributed_state.get_room(room_id) else {
            let message = "Room does not exist";
            send_error(sessions, participant_id, "ROOM_NOT_FOUND", message);
            return false;
        };
        assert_eq!(room.room_id(), room_id);
        // Unnamed rooms have the name "": only a "*" token grants them
        if !granted(sessions, participant_id, Some(room.name())) {
            send_error(sessions, participant_id, "FORBIDDEN", FORBIDDEN_MESSAGE);
            return false;
        }
        true
    }

    pub fn handle_join(
        &mut self,
        participant_id: u64,
        room_id: u64,
        participant_name: &str,
        sessions: &mut HashMap<u64, ParticipantHandle>,
    ) {
        if participant_id == 0 || room_id == 0 {
            send_error(
                sessions,
                participant_id,
                "INVALID_INPUT",
                "Invalid participant or room ID",
            );
            return;
        }

        if participant_name.len() > MAX_PARTICIPANT_NAME_LEN {
            let message = format!("Name longer than {MAX_PARTICIPANT_NAME_LEN} bytes");
            send_error(sessions, participant_id, "INVALID_INPUT", &message);
            return;
        }
        // Room ids are u32: a larger id names no room (it must not wrap to one)
        let Ok(room_id_u32) = u32::try_from(room_id) else {
            send_error(
                sessions,
                participant_id,
                "ROOM_NOT_FOUND",
                "Room does not exist",
            );
            return;
        };

        // One room per participant: switching would keep the old room's membership,
        // tracks and subscriptions. Leave (which ends the session) first.
        if sessions
            .get(&participant_id)
            .is_some_and(|h| h.room_id.is_some())
        {
            send_error(
                sessions,
                participant_id,
                "ALREADY_IN_ROOM",
                "Already in a room",
            );
            return;
        }

        if !self.room_granted(participant_id, room_id_u32, sessions) {
            return;
        }

        let current_count = self.distributed_state.participant_count(room_id_u32);
        if current_count >= MAX_PARTICIPANTS_PER_ROOM as usize {
            send_error(sessions, participant_id, "ROOM_FULL", "Room is full");
            return;
        }

        if let Err(e) = self
            .distributed_state
            .add_participant(room_id_u32, participant_id)
        {
            send_error(sessions, participant_id, "JOIN_FAILED", &format!("{:?}", e));
            return;
        }

        if let Some(handle) = sessions.get_mut(&participant_id) {
            handle.room_id = Some(room_id_u32);
        }

        // Build response with existing participants and tracks
        let participants = self.distributed_state.get_participants(room_id_u32);
        let participant_infos: Vec<crate::signal::ParticipantInfo> = participants
            .iter()
            .filter(|&&pid| pid != participant_id)
            .take(100)
            .map(|&pid| crate::signal::ParticipantInfo {
                id: pid,
                name: String::new(),
            })
            .collect();

        // Collect published tracks from other participants
        let mut track_infos: Vec<crate::signal::TrackInfo> = Vec::with_capacity(64);
        for &pid in &participants {
            if pid == participant_id {
                continue;
            }
            if let Some(handle) = sessions.get(&pid) {
                for &tid in &handle.published_tracks {
                    if track_infos.len() >= 64 {
                        break;
                    }
                    let (kind, content) = match self.distributed_state.get_track(tid) {
                        Some(ti) => (
                            if ti.track_type == 0 { "audio" } else { "video" },
                            match ti.content_type {
                                1 => "screen",
                                2 => "audio",
                                _ => "camera",
                            },
                        ),
                        None => ("video", "camera"),
                    };
                    track_infos.push(crate::signal::TrackInfo {
                        track_id: tid,
                        publisher_id: pid,
                        kind: kind.to_string(),
                        content: content.to_string(),
                    });
                }
            }
        }

        send_to(
            sessions,
            participant_id,
            SignalMessage::Joined {
                participant_id,
                room_id,
                participants: participant_infos,
                tracks: track_infos,
            },
        );

        // Notify existing participants
        let notify_count = participants.len().min(MAX_PARTICIPANTS_PER_ROOM as usize);
        for (i, &pid) in participants.iter().enumerate() {
            if i >= notify_count {
                break;
            }
            if pid == participant_id {
                continue;
            }
            send_to(
                sessions,
                pid,
                SignalMessage::ParticipantJoined {
                    participant_id,
                    name: participant_name.to_string(),
                },
            );
        }

        info!("Participant {} joined room {}", participant_id, room_id);
    }

    pub fn handle_leave(
        &mut self,
        participant_id: u64,
        sessions: &mut HashMap<u64, ParticipantHandle>,
    ) {
        if participant_id == 0 {
            return;
        }
        self.cleanup_participant_room(participant_id, sessions);
        self.release_created_rooms(participant_id);
    }

    pub fn handle_disconnected(
        &mut self,
        participant_id: u64,
        sessions: &mut HashMap<u64, ParticipantHandle>,
    ) {
        if participant_id == 0 {
            return;
        }
        self.cleanup_participant_room(participant_id, sessions);
        self.release_created_rooms(participant_id);
    }

    /// The rooms `participant_id` created that nobody is in are removed (after
    /// its own membership was cleaned up).
    fn release_created_rooms(&mut self, participant_id: u64) {
        let Some(rooms) = self.created.remove(&participant_id) else {
            return;
        };
        assert!(rooms.len() <= MAX_ROOMS_PER_CREATOR);
        for room in rooms {
            if self.distributed_state.room_exists(room)
                && self.distributed_state.participant_count(room) == 0
            {
                self.distributed_state.remove_room(room);
                self.room_names.retain(|_, &mut v| v != room);
                debug!("Room {} released: empty when its creator left", room);
            }
        }
    }

    /// Clean up room membership and notify peers.
    /// Does NOT remove the ParticipantHandle — the dispatcher does that.
    pub fn cleanup_participant_room(
        &mut self,
        participant_id: u64,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        let room_id = match sessions.get(&participant_id).and_then(|h| h.room_id) {
            Some(id) => id,
            None => return,
        };

        if let Err(e) = self
            .distributed_state
            .remove_participant(room_id, participant_id)
        {
            debug!(
                "Failed to remove participant from distributed state: {:?}",
                e
            );
        }

        // Notify remaining participants
        let participants = self.distributed_state.get_participants(room_id);
        let notify_count = participants.len().min(MAX_PARTICIPANTS_PER_ROOM as usize);
        for (i, &pid) in participants.iter().enumerate() {
            if i >= notify_count {
                break;
            }
            if pid == participant_id {
                continue;
            }
            send_to(
                sessions,
                pid,
                SignalMessage::ParticipantLeft { participant_id },
            );
        }

        // Clean up empty room
        if participants.is_empty() {
            if !self.distributed_state.remove_room(room_id) {
                debug!(
                    "Room {} not found in distributed state during cleanup",
                    room_id
                );
            }
            self.room_names.retain(|_, &mut v| v != room_id);
        }

        info!(
            "Participant {} removed from room {}",
            participant_id, room_id
        );
    }
}

/// Send a message to a participant via their outbound channel.
fn send_to(sessions: &HashMap<u64, ParticipantHandle>, participant_id: u64, msg: SignalMessage) {
    if let Some(handle) = sessions.get(&participant_id) {
        if handle.outbound_tx.try_send(msg).is_err() {
            debug!(
                "Failed to send to participant {} — channel closed",
                participant_id
            );
        }
    }
}

fn send_error(
    sessions: &HashMap<u64, ParticipantHandle>,
    participant_id: u64,
    code: &str,
    message: &str,
) {
    send_to(
        sessions,
        participant_id,
        SignalMessage::Error {
            code: code.to_string(),
            message: message.to_string(),
        },
    );
}
