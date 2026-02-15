// ============================================================================
// Nexus SDK — Room
// Manages room state: participants, available tracks, join/leave lifecycle.
// ============================================================================

import type { Signaling } from './signaling.js';
import type {
  SignalMessage,
  JoinedMsg,
  ParticipantInfo,
  ContentType,
  TrackKind,
} from './types.js';

/** Remote track info as seen by the room. */
export interface RemoteTrackInfo {
  trackId: number;
  publisherId: number;
  kind: TrackKind;
  content: ContentType;
}

export class Room {
  /** Our participant ID (set after join). */
  participantId = 0;
  /** Room ID. */
  roomId = 0;
  /** Remote participants. */
  readonly participants = new Map<number, ParticipantInfo>();
  /** Available remote tracks. */
  readonly remoteTracks = new Map<number, RemoteTrackInfo>();

  private signaling: Signaling;

  // Callbacks — set by NexusClient to bridge into EventEmitter
  onParticipantJoined: ((id: number, name: string) => void) | null = null;
  onParticipantLeft: ((id: number) => void) | null = null;
  onTrackPublished: ((info: RemoteTrackInfo) => void) | null = null;
  onTrackUnpublished: ((trackId: number) => void) | null = null;

  constructor(signaling: Signaling) {
    this.signaling = signaling;
  }

  /** Join a room. Resolves with the Joined response. */
  async join(roomId: number, name: string): Promise<JoinedMsg> {
    const resp = await this.signaling.request<JoinedMsg>(
      { type: 'Join', room_id: roomId, participant_name: name },
      'Joined',
    );

    this.participantId = resp.participant_id;
    this.roomId = resp.room_id;

    // Populate initial participants
    for (const p of resp.participants) {
      this.participants.set(p.id, p);
    }

    return resp;
  }

  /** Leave the room. */
  leave(): void {
    this.signaling.send({ type: 'Leave' });
    this.participants.clear();
    this.remoteTracks.clear();
    this.participantId = 0;
    this.roomId = 0;
  }

  /** Handle an incoming signal message. Returns true if consumed. */
  handleMessage(msg: SignalMessage): boolean {
    switch (msg.type) {
      case 'ParticipantJoined': {
        const info: ParticipantInfo = {
          id: msg.participant_id,
          name: msg.name,
        };
        this.participants.set(msg.participant_id, info);
        this.onParticipantJoined?.(msg.participant_id, msg.name);
        return true;
      }
      case 'ParticipantLeft':
        this.participants.delete(msg.participant_id);
        // Remove tracks from this participant
        for (const [tid, t] of this.remoteTracks) {
          if (t.publisherId === msg.participant_id) {
            this.remoteTracks.delete(tid);
          }
        }
        this.onParticipantLeft?.(msg.participant_id);
        return true;

      case 'TrackPublished': {
        const track: RemoteTrackInfo = {
          trackId: msg.track_id,
          publisherId: msg.publisher_id,
          kind: msg.kind as TrackKind,
          content: msg.content as ContentType,
        };
        this.remoteTracks.set(msg.track_id, track);
        this.onTrackPublished?.(track);
        return true;
      }
      case 'TrackUnpublished':
        this.remoteTracks.delete(msg.track_id);
        this.onTrackUnpublished?.(msg.track_id);
        return true;

      default:
        return false;
    }
  }
}
