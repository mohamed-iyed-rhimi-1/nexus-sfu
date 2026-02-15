// ============================================================================
// Nexus SDK — NexusClient
// Main entry point. Orchestrates signaling, room, publisher, subscriber,
// and viewport into a single cohesive API.
// ============================================================================

import { EventEmitter } from './events.js';
import { Signaling } from './signaling.js';
import { Room } from './room.js';
import { Publisher, type LocalTrack } from './publisher.js';
import { Subscriber, type RemoteSubscription } from './subscriber.js';
import { ViewportManager } from './viewport.js';
import type { NexusConfig, NexusEvents, JoinedMsg, SignalMessage } from './types.js';

export class NexusClient extends EventEmitter<NexusEvents> {
  readonly signaling: Signaling;
  readonly room: Room;
  readonly viewport: ViewportManager;
  private publisher: Publisher | null = null;
  private subscriber: Subscriber | null = null;
  private rtcConfig: RTCConfiguration;

  constructor(config: NexusConfig, rtcConfig?: RTCConfiguration) {
    super();
    this.rtcConfig = rtcConfig ?? {};

    this.signaling = new Signaling(config);
    this.room = new Room(this.signaling);
    this.viewport = new ViewportManager(this.signaling);

    this.wireCallbacks();
  }

  /** Connect to the Nexus SFU server. */
  async connect(): Promise<void> {
    await this.signaling.connect();

    // Create peer connections after signaling is up
    this.publisher = new Publisher(
      this.signaling,
      () => this.room.participantId,
      this.rtcConfig,
    );
    this.subscriber = new Subscriber(this.signaling, this.rtcConfig);

    this.subscriber.onTrackReceived = (trackId, track, stream) => {
      this.emit('trackSubscribed', { trackId, track, stream });
    };

    this.emit('connected', undefined as never);
  }

  /** Join a room. */
  async join(roomId: number, name: string): Promise<JoinedMsg> {
    return this.room.join(roomId, name);
  }

  /** Leave the current room. */
  leave(): void {
    this.room.leave();
  }

  // -------------------------------------------------------------------------
  // Publishing
  // -------------------------------------------------------------------------

  /** Publish camera video with optional simulcast. */
  async publishCamera(
    constraints?: MediaTrackConstraints,
  ): Promise<LocalTrack> {
    this.ensurePublisher();
    return this.publisher!.publishCamera(constraints);
  }

  /** Publish microphone audio. */
  async publishMicrophone(
    constraints?: MediaTrackConstraints,
  ): Promise<LocalTrack> {
    this.ensurePublisher();
    return this.publisher!.publishMicrophone(constraints);
  }

  /** Publish screen share (single high-quality layer, no simulcast). */
  async publishScreen(
    constraints?: DisplayMediaStreamOptions,
  ): Promise<LocalTrack> {
    this.ensurePublisher();
    return this.publisher!.publishScreen(constraints);
  }

  /** Stop publishing a track. */
  async unpublish(mediaTrackId: string): Promise<void> {
    await this.publisher?.unpublish(mediaTrackId);
  }

  // -------------------------------------------------------------------------
  // Subscribing
  // -------------------------------------------------------------------------

  /** Subscribe to a remote track. */
  async subscribe(trackId: number): Promise<RemoteSubscription> {
    this.ensureSubscriber();
    return this.subscriber!.subscribe(trackId);
  }

  /** Unsubscribe from a remote track. */
  unsubscribe(trackId: number): void {
    this.subscriber?.unsubscribe(trackId);
    this.emit('trackUnsubscribed', { trackId });
  }

  /** Attach a subscribed track to a DOM element. */
  attach(trackId: number, element: HTMLMediaElement): boolean {
    return this.subscriber?.attach(trackId, element) ?? false;
  }

  /** Detach a track from its DOM element. */
  detach(trackId: number): void {
    this.subscriber?.detach(trackId);
  }

  // -------------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------------

  /** Disconnect and clean up all resources. */
  close(): void {
    this.viewport.destroy();
    this.publisher?.close();
    this.subscriber?.close();
    this.signaling.close();
    this.removeAll();
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private wireCallbacks(): void {
    // Route signaling messages to the right handler
    this.signaling.onMessage((msg: SignalMessage) => {
      // Room handles participant/track notifications
      if (this.room.handleMessage(msg)) return;
      // Publisher handles answers
      if (this.publisher?.handleMessage(msg)) return;
      // Subscriber handles offers from SFU
      this.subscriber?.handleMessage(msg);

      // Surface errors
      if (msg.type === 'Error') {
        this.emit('error', { code: msg.code, message: msg.message });
      }
      if (msg.type === 'ServerShutdown') {
        this.emit('serverShutdown', {
          reason: msg.reason,
          drainSeconds: msg.drain_seconds,
        });
      }
    });

    // Reconnect events
    this.signaling.onDisconnect = (reason) => {
      this.emit('disconnected', { reason });
    };
    this.signaling.onReconnecting = (attempt) => {
      this.emit('reconnecting', { attempt });
    };

    // Room → client events
    this.room.onParticipantJoined = (participantId, name) => {
      this.emit('participantJoined', { participantId, name });
    };
    this.room.onParticipantLeft = (participantId) => {
      this.emit('participantLeft', { participantId });
    };
    this.room.onTrackPublished = (info) => {
      this.emit('trackPublished', {
        publisherId: info.publisherId,
        trackId: info.trackId,
        kind: info.kind,
        content: info.content,
      });
    };
    this.room.onTrackUnpublished = (trackId) => {
      this.emit('trackUnpublished', { trackId });
    };
  }

  private ensurePublisher(): void {
    if (!this.publisher) {
      throw new Error('Not connected. Call connect() first.');
    }
  }

  private ensureSubscriber(): void {
    if (!this.subscriber) {
      throw new Error('Not connected. Call connect() first.');
    }
  }
}
