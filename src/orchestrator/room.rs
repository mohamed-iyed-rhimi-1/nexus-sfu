//! RoomManager: room CRUD, participant join/leave, notifications.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::signal::SignalMessage;
use nexus_state::DistributedState;

use super::ParticipantHandle;

const MAX_ROOMS: usize = 10_000;
const MAX_PARTICIPANTS_PER_ROOM: u32 = 1_000;

pub struct RoomManager {
    room_names: HashMap<String, u32>,
    next_room_id: u32,
    distributed_state: Arc<DistributedState>,
}

impl RoomManager {
    pub fn new(distributed_state: Arc<DistributedState>) -> Self {
        Self {
            room_names: HashMap::with_capacity(256),
            next_room_id: 1,
            distributed_state,
        }
    }

    pub fn handle_create(
        &mut self,
        participant_id: u64,
        room_name: Option<String>,
        sessions: &HashMap<u64, ParticipantHandle>,
    ) {
        assert!(participant_id != 0);

        // Idempotent: return existing room if name matches
        if let Some(ref name) = room_name {
            if let Some(&existing_id) = self.room_names.get(name) {
                send_to(sessions, participant_id, SignalMessage::Created {
                    room_id: existing_id as u64,
                    room_name: Some(name.clone()),
                });
                return;
            }
        }

        if self.room_names.len() >= MAX_ROOMS {
            send_error(sessions, participant_id, "ROOM_LIMIT", "Maximum rooms reached");
            return;
        }

        let room_id = self.next_room_id;
        self.next_room_id += 1;

        if let Some(ref name) = room_name {
            self.room_names.insert(name.clone(), room_id);
        }

        if let Err(e) = self.distributed_state.create_room(
            room_id,
            room_name.clone().unwrap_or_default(),
            MAX_PARTICIPANTS_PER_ROOM,
        ) {
            warn!("Failed to create room in CRDT: {:?}", e);
        }

        send_to(sessions, participant_id, SignalMessage::Created {
            room_id: room_id as u64,
            room_name,
        });

        info!("Room {} created by participant {}", room_id, participant_id);
    }

    pub fn handle_join(
        &mut self,
        participant_id: u64,
        room_id: u64,
        participant_name: &str,
        sessions: &mut HashMap<u64, ParticipantHandle>,
    ) {
        assert!(participant_id != 0);
        assert!(room_id > 0);

        let room_id_u32 = room_id as u32;

        if !self.distributed_state.room_exists(room_id_u32) {
            send_error(sessions, participant_id, "ROOM_NOT_FOUND", "Room does not exist");
            return;
        }

        let current_count = self.distributed_state.participant_count(room_id_u32);
        if current_count >= MAX_PARTICIPANTS_PER_ROOM as usize {
            send_error(sessions, participant_id, "ROOM_FULL", "Room is full");
            return;
        }

        if let Err(e) = self.distributed_state.add_participant(room_id_u32, participant_id) {
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
            .map(|&pid| crate::signal::ParticipantInfo { id: pid, name: String::new() })
            .collect();

        // Collect published tracks from other participants
        let mut track_infos: Vec<crate::signal::TrackInfo> = Vec::with_capacity(64);
        for &pid in &participants {
            if pid == participant_id { continue; }
            if let Some(handle) = sessions.get(&pid) {
                for &tid in &handle.published_tracks {
                    if track_infos.len() >= 64 { break; }
                    let (kind, content) = match self.distributed_state.get_track(tid) {
                        Some(ti) => (
                            if ti.track_type == 0 { "audio" } else { "video" },
                            match ti.content_type { 1 => "screen", 2 => "audio", _ => "camera" },
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

        send_to(sessions, participant_id, SignalMessage::Joined {
            participant_id,
            room_id,
            participants: participant_infos,
            tracks: track_infos,
        });

        // Notify existing participants
        let notify_count = participants.len().min(MAX_PARTICIPANTS_PER_ROOM as usize);
        for (i, &pid) in participants.iter().enumerate() {
            if i >= notify_count { break; }
            if pid == participant_id { continue; }
            send_to(sessions, pid, SignalMessage::ParticipantJoined {
                participant_id,
                name: participant_name.to_string(),
            });
        }

        info!("Participant {} joined room {}", participant_id, room_id);
    }

    pub fn handle_leave(&mut self, participant_id: u64, sessions: &mut HashMap<u64, ParticipantHandle>) {
        assert!(participant_id != 0);
        self.cleanup_participant_room(participant_id, sessions);
    }

    pub fn handle_disconnected(&mut self, participant_id: u64, sessions: &mut HashMap<u64, ParticipantHandle>) {
        assert!(participant_id != 0);
        self.cleanup_participant_room(participant_id, sessions);
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

        if let Err(e) = self.distributed_state.remove_participant(room_id, participant_id) {
            debug!("Failed to remove participant from distributed state: {:?}", e);
        }

        // Notify remaining participants
        let participants = self.distributed_state.get_participants(room_id);
        let notify_count = participants.len().min(MAX_PARTICIPANTS_PER_ROOM as usize);
        for (i, &pid) in participants.iter().enumerate() {
            if i >= notify_count { break; }
            if pid == participant_id { continue; }
            send_to(sessions, pid, SignalMessage::ParticipantLeft { participant_id });
        }

        // Clean up empty room
        if participants.is_empty() {
            if !self.distributed_state.remove_room(room_id) {
                debug!("Room {} not found in distributed state during cleanup", room_id);
            }
            self.room_names.retain(|_, &mut v| v != room_id);
        }

        info!("Participant {} removed from room {}", participant_id, room_id);
    }
}

/// Send a message to a participant via their outbound channel.
fn send_to(sessions: &HashMap<u64, ParticipantHandle>, participant_id: u64, msg: SignalMessage) {
    if let Some(handle) = sessions.get(&participant_id) {
        if handle.outbound_tx.send(msg).is_err() {
            debug!("Failed to send to participant {} — channel closed", participant_id);
        }
    }
}

fn send_error(sessions: &HashMap<u64, ParticipantHandle>, participant_id: u64, code: &str, message: &str) {
    send_to(sessions, participant_id, SignalMessage::Error {
        code: code.to_string(),
        message: message.to_string(),
    });
}
