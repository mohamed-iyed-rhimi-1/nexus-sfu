// ============================================================================
// Nexus SDK — Types
// Mirrors crates/nexus-signal/src/protocol/messages.rs exactly.
// The server uses #[serde(tag = "type")] so JSON has { "type": "Join", ... }
// ============================================================================

/** Content type for published tracks. */
export type ContentType = 'camera' | 'screen' | 'audio';

/** Track kind. */
export type TrackKind = 'audio' | 'video';

/** Participant info returned in Joined message. */
export interface ParticipantInfo {
  id: number;
  name: string;
}

// ---------------------------------------------------------------------------
// Signal messages — discriminated union on "type" field
// ---------------------------------------------------------------------------

export interface CreateMsg {
  type: 'Create';
  room_name?: string;
}

export interface CreatedMsg {
  type: 'Created';
  room_id: number;
  room_name?: string;
}

export interface JoinMsg {
  type: 'Join';
  room_id: number;
  participant_name: string;
}

export interface JoinedMsg {
  type: 'Joined';
  participant_id: number;
  room_id: number;
  participants: ParticipantInfo[];
  tracks: number[];
}

export interface LeaveMsg {
  type: 'Leave';
}

export interface ParticipantJoinedMsg {
  type: 'ParticipantJoined';
  participant_id: number;
  name: string;
}

export interface ParticipantLeftMsg {
  type: 'ParticipantLeft';
  participant_id: number;
}

export interface OfferMsg {
  type: 'Offer';
  target_participant_id?: number;
  sdp: string;
}

export interface OfferReceivedMsg {
  type: 'OfferReceived';
  from_participant_id: number;
  sdp: string;
}

export interface AnswerMsg {
  type: 'Answer';
  target_participant_id: number;
  sdp: string;
}

export interface AnswerReceivedMsg {
  type: 'AnswerReceived';
  from_participant_id: number;
  sdp: string;
}

export interface IceCandidateMsg {
  type: 'IceCandidate';
  target_participant_id: number;
  candidate: string;
  sdp_mid?: string;
  sdp_mline_index?: number;
}

export interface EndOfCandidatesMsg {
  type: 'EndOfCandidates';
}

export interface StatsMsg {
  type: 'Stats';
  tracks_count: number;
  packets_sent: number;
  packets_received: number;
  bytes_sent: number;
  bytes_received: number;
}

export interface ErrorMsg {
  type: 'Error';
  code: string;
  message: string;
}

export interface PingMsg {
  type: 'Ping';
}

export interface PongMsg {
  type: 'Pong';
}

export interface SubscribeMsg {
  type: 'Subscribe';
  track_id: number;
}

export interface SubscribedMsg {
  type: 'Subscribed';
  track_id: number;
  subscriber_id: number;
}

export interface UnsubscribeMsg {
  type: 'Unsubscribe';
  track_id: number;
}

export interface UnsubscribedMsg {
  type: 'Unsubscribed';
  track_id: number;
}

export interface TrackPublishedMsg {
  type: 'TrackPublished';
  publisher_id: number;
  track_id: number;
  kind: string;
  content: string;
}

export interface TrackUnpublishedMsg {
  type: 'TrackUnpublished';
  track_id: number;
}

export interface ServerShutdownMsg {
  type: 'ServerShutdown';
  reason: string;
  drain_seconds: number;
}

export interface ViewportMsg {
  type: 'Viewport';
  visible: number[];
  pinned: number[];
}

export interface ViewportUpdatedMsg {
  type: 'ViewportUpdated';
  visible_count: number;
  pinned_count: number;
}

export interface SetContentMsg {
  type: 'SetContent';
  track_id: number;
  content: string;
}

export interface ContentSetMsg {
  type: 'ContentSet';
  track_id: number;
  content: string;
}

/** Union of all signal messages. */
export type SignalMessage =
  | CreateMsg
  | CreatedMsg
  | JoinMsg
  | JoinedMsg
  | LeaveMsg
  | ParticipantJoinedMsg
  | ParticipantLeftMsg
  | OfferMsg
  | OfferReceivedMsg
  | AnswerMsg
  | AnswerReceivedMsg
  | IceCandidateMsg
  | EndOfCandidatesMsg
  | StatsMsg
  | ErrorMsg
  | PingMsg
  | PongMsg
  | SubscribeMsg
  | SubscribedMsg
  | UnsubscribeMsg
  | UnsubscribedMsg
  | TrackPublishedMsg
  | TrackUnpublishedMsg
  | ServerShutdownMsg
  | ViewportMsg
  | ViewportUpdatedMsg
  | SetContentMsg
  | ContentSetMsg;

/** Extract message by type discriminator. */
export type MessageOfType<T extends SignalMessage['type']> = Extract<
  SignalMessage,
  { type: T }
>;

// ---------------------------------------------------------------------------
// Client configuration
// ---------------------------------------------------------------------------

export type TransportType = 'websocket' | 'quic' | 'auto';

export interface NexusConfig {
  /** Server URL. ws:// or wss:// for WebSocket, https:// for WebTransport. */
  url: string;
  /** JWT auth token. */
  token?: string;
  /** Transport preference. 'auto' tries QUIC first, falls back to WS. */
  transport?: TransportType;
  /** Reconnect attempts before giving up. Default: 5. */
  maxReconnectAttempts?: number;
  /** Ping interval in ms. Default: 30000. */
  pingIntervalMs?: number;
}

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

export interface NexusEvents {
  connected: void;
  disconnected: { reason: string };
  reconnecting: { attempt: number };
  participantJoined: { participantId: number; name: string };
  participantLeft: { participantId: number };
  trackPublished: {
    publisherId: number;
    trackId: number;
    kind: TrackKind;
    content: ContentType;
  };
  trackUnpublished: { trackId: number };
  trackSubscribed: {
    trackId: number;
    track: MediaStreamTrack;
    stream: MediaStream;
  };
  trackUnsubscribed: { trackId: number };
  serverShutdown: { reason: string; drainSeconds: number };
  error: { code: string; message: string };
}
