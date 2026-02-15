// ============================================================================
// Nexus SDK — Public API
// ============================================================================

export { NexusClient } from './client.js';
export { Signaling } from './signaling.js';
export { Room, type RemoteTrackInfo } from './room.js';
export { Publisher, type LocalTrack } from './publisher.js';
export { Subscriber, type RemoteSubscription } from './subscriber.js';
export { ViewportManager } from './viewport.js';
export { EventEmitter } from './events.js';

// Transport layer
export type { SignalingTransport, TransportState } from './transport/transport.js';
export { WebSocketTransport } from './transport/ws.js';
export { QuicTransport } from './transport/quic.js';

// Types
export type {
  SignalMessage,
  NexusConfig,
  NexusEvents,
  ParticipantInfo,
  ContentType,
  TrackKind,
  TransportType,
} from './types.js';
