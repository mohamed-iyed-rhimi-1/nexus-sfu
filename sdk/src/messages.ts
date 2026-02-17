// Discriminated union matching Rust SignalMessage enum

export type SignalMessage =
  | { type: 'Create'; room_name?: string }
  | { type: 'Created'; room_id: number; room_name?: string }
  | { type: 'Join'; room_id: number; participant_name: string }
  | { type: 'Joined'; participant_id: number; room_id: number; participants: ParticipantInfo[]; tracks: TrackInfo[] }
  | { type: 'Leave' }
  | { type: 'ParticipantJoined'; participant_id: number; name: string }
  | { type: 'ParticipantLeft'; participant_id: number }
  | { type: 'Publish'; kinds: string[]; contents: string[] }
  | { type: 'Unpublish'; track_ids: number[] }
  | { type: 'Offer'; sdp: string }
  | { type: 'Answer'; sdp: string }
  | { type: 'IceCandidate'; candidate: string; sdp_mid?: string; sdp_mline_index?: number }
  | { type: 'EndOfCandidates' }
  | { type: 'Subscribe'; track_ids: number[] }
  | { type: 'Subscribed'; track_ids: number[] }
  | { type: 'Unsubscribe'; track_ids: number[] }
  | { type: 'Unsubscribed'; track_ids: number[] }
  | { type: 'TrackPublished'; publisher_id: number; track_id: number; kind: string; content: string }
  | { type: 'TrackUnpublished'; track_id: number }
  | { type: 'Viewport'; visible: number[]; pinned: number[] }
  | { type: 'ViewportUpdated'; visible_count: number; pinned_count: number }
  | { type: 'SetContent'; track_id: number; content: string }
  | { type: 'ContentSet'; track_id: number; content: string }
  | { type: 'Ping' }
  | { type: 'Pong' }
  | { type: 'Stats'; tracks_count: number; packets_sent: number; packets_received: number; bytes_sent: number; bytes_received: number }
  | { type: 'Error'; code: string; message: string }
  | { type: 'ServerShutdown'; reason: string; drain_seconds: number };

export interface ParticipantInfo {
  id: number;
  name: string;
}

export interface TrackInfo {
  track_id: number;
  publisher_id: number;
  kind: string;
  content: string;
}
