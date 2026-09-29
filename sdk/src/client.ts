import { SignalingTransport, TokenSource } from './signaling';
import { OfferTrack, SignalMessage, TrackInfo } from './messages';
import { EventEmitter } from './events';
import { NexusError } from './errors';

export interface NexusClientConfig {
  url: string;
  /**
   * JWT sent in the auth handshake the SFU requires on connect.
   * Pass a function to fetch a fresh token on every (re)connect.
   */
  token?: TokenSource;
  /**
   * ICE servers for the RTCPeerConnection. Default none: the SFU is ICE-lite and
   * announces its host candidates, so the browser needs no STUN server.
   */
  iceServers?: RTCIceServer[];
  /** How long createRoom, join and publish wait for the SFU (default 10 s). */
  requestTimeoutMs?: number;
}

/** The SFU refuses a Subscribe with more ids (`MAX_TRACKS_PER_REQUEST`). */
export const MAX_TRACKS_PER_REQUEST = 10;

/** How long request-reply calls (createRoom, join, publish) wait for the SFU by default. */
const REQUEST_TIMEOUT_MS = 10000;

/**
 * Errors with which the SFU refuses a `Publish` (no offer follows): at once, or when
 * a publish it queued behind an outstanding offer comes up after that offer's answer.
 */
const PUBLISH_REFUSALS = new Set(['NOT_IN_ROOM', 'TOO_MANY_TRACKS', 'SESSION_FAILED', 'OFFER_FAILED']);

/** Errors with which the SFU refuses one published m-line of an answer, in m-line order. */
const MLINE_REFUSALS = new Set(['TOO_MANY_TRACKS', 'INVALID_TRACK', 'SSRC_COLLISION', 'DUPLICATE_SSRC']);

interface PendingPublish {
  resolve: (trackId: number) => void;
  reject: (err: NexusError) => void;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * A request whose replies end at the next `Pong`. The SFU's errors carry no request
 * id, but it handles a participant's messages in order and replies to each before
 * reading the next, so a `Ping` sent after a request fences off that request's replies.
 */
type Fence =
  /** `offered`: the SFU's reply included an offer (else it queued the publish). */
  | { kind: 'publish'; track: MediaStreamTrack; offered: boolean }
  /** Tracks attached in this answer that have neither a `Published` nor a refusal yet. */
  | { kind: 'answer'; tracks: MediaStreamTrack[] }
  | { kind: 'subscribe' }
  /** Create, Join, Unpublish, Unsubscribe: an error goes to `onError`, if any. */
  | { kind: 'request'; onError?: (err: NexusError) => void }
  | { kind: 'keepalive' };

/**
 * A participant's connection to the SFU.
 *
 * Errors: an SFU error is matched to the request it answers (see `Fence`). A refused
 * publish rejects its `publish()` promise and frees the track to be published again;
 * errors of other requests (Subscribe, Unpublish, ...) only reach the `error` event
 * (createRoom and join reject on their own errors) and never reject a publish. If a
 * publish times out and the SFU registers the track later, `lateTrackPublished`
 * carries its id, to `unpublish` it. If a `Ping` is lost (the SFU drops messages
 * above 100 per second), errors can be matched to the wrong request until the
 * connection ends; a publish that never completes still times out and is cleaned up.
 * Messages sent with `send()` carry no fence.
 */
export class NexusClient extends EventEmitter {
  private signaling: SignalingTransport;
  private iceServers: RTCIceServer[];
  private requestTimeoutMs: number;
  private pc: RTCPeerConnection | null = null;
  private participantId: number | null = null;
  private roomId: number | null = null;
  private localTracks = new Map<string, MediaStreamTrack>();
  private remoteTracks = new Map<number, MediaStream>();
  /** Which subscribed track each receiving m-line carries, from the SFU's offers. */
  private trackIdByMid = new Map<string, number>();
  private offerPending = false;
  /** Local tracks waiting for the SFU's offer to give them an m-line. */
  private unattachedTracks: MediaStreamTrack[] = [];
  private pendingActions: (() => void)[] = [];
  /** The local track sent on each publish m-line, by mid. */
  private localTrackByMid = new Map<string, MediaStreamTrack>();
  /** This participant's published tracks: track id → publish m-line mid. */
  private ownTrackMids = new Map<number, string>();
  /** Publishes waiting for the SFU's `Published`, by local track. */
  private pendingPublishes = new Map<MediaStreamTrack, PendingPublish>();
  /** Requests sent with a `Ping` behind them, oldest first; each `Pong` ends one. */
  private fences: Fence[] = [];
  /**
   * Tracks whose `Publish` the SFU queued behind an outstanding offer. It merges them
   * into one publish after that offer's answer, and one offer or one refusal covers all.
   */
  private serverQueued: MediaStreamTrack[] = [];

  constructor(config: NexusClientConfig) {
    super();
    this.signaling = new SignalingTransport(config.url, config.token);
    this.iceServers = config.iceServers ?? [];
    this.requestTimeoutMs = config.requestTimeoutMs ?? REQUEST_TIMEOUT_MS;
    this.setupSignaling();
  }

  get participant(): number | null {
    return this.participantId;
  }

  get room(): number | null {
    return this.roomId;
  }

  async connect(): Promise<void> {
    await this.signaling.connect();
    this.emit('connected');
  }

  /**
   * Create a room, or get the id of the room with this name if it exists (the SFU
   * looks rooms up by name). Does not join it. The token's `rooms` claim must name
   * the room (or be `"*"`); otherwise this and `join` reject with `FORBIDDEN`.
   */
  async createRoom(name?: string): Promise<number> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.signaling.off('message', handler);
        reject(new NexusError('TIMEOUT', 'Create timeout'));
      }, this.requestTimeoutMs);

      const handler = (msg: SignalMessage) => {
        if (msg.type === 'Created') {
          clearTimeout(timeout);
          this.signaling.off('message', handler);
          resolve(msg.room_id);
        }
      };
      // Only an error answering this Create rejects it (see `Fence`)
      const onError = (err: NexusError) => {
        clearTimeout(timeout);
        this.signaling.off('message', handler);
        reject(err);
      };

      this.signaling.on('message', handler);
      this.request({ type: 'Create', room_name: name }, { kind: 'request', onError });
    });
  }

  async join(roomId: number, name: string): Promise<{ participantId: number; participants: any[]; tracks: TrackInfo[] }> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.signaling.off('message', handler);
        reject(new NexusError('TIMEOUT', 'Join timeout'));
      }, this.requestTimeoutMs);
      
      const handler = (msg: SignalMessage) => {
        if (msg.type === 'Joined') {
          clearTimeout(timeout);
          this.signaling.off('message', handler);
          this.participantId = msg.participant_id;
          this.roomId = msg.room_id;
          resolve({
            participantId: msg.participant_id,
            participants: msg.participants,
            tracks: msg.tracks,
          });
        }
      };
      const onError = (err: NexusError) => {
        clearTimeout(timeout);
        this.signaling.off('message', handler);
        reject(err);
      };

      this.signaling.on('message', handler);
      this.request({ type: 'Join', room_id: roomId, participant_name: name }, { kind: 'request', onError });
    });
  }

  async publishCamera(): Promise<MediaStreamTrack> {
    const stream = await navigator.mediaDevices.getUserMedia({ video: true });
    const track = stream.getVideoTracks()[0];
    await this.publish(track, 'camera');
    return track;
  }

  async publishMicrophone(): Promise<MediaStreamTrack> {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const track = stream.getAudioTracks()[0];
    await this.publish(track, 'audio');
    return track;
  }

  async publishScreen(): Promise<MediaStreamTrack> {
    const stream = await navigator.mediaDevices.getDisplayMedia({ video: true });
    const track = stream.getVideoTracks()[0];
    await this.publish(track, 'screen');
    return track;
  }

  /**
   * Publish a local track (also one published before and unpublished). Resolves with
   * the track id the SFU assigned once it registered the track from the answer.
   */
  async publish(track: MediaStreamTrack, content?: string): Promise<number> {
    if (this.pendingPublishes.has(track) || this.localTracks.has(track.id)) {
      throw new NexusError('ALREADY_PUBLISHED', 'Track is published or being published');
    }
    const kind = track.kind === 'audio' ? 'audio' : 'video';
    const published = new Promise<number>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.failPublish(track, new NexusError('TIMEOUT', 'Publish timeout'));
      }, this.requestTimeoutMs);
      this.pendingPublishes.set(track, { resolve, reject, timer });
    });
    await this.publishTrack(track, kind, content ?? (kind === 'audio' ? 'audio' : 'camera'));
    return published;
  }

  /**
   * Stop publishing a track. The SFU sends this participant no new offer: the m-line
   * is detached here and reused by the next publish or subscription of its kind.
   * The MediaStreamTrack is not stopped, so it can be published again.
   */
  async unpublish(trackId: number): Promise<void> {
    const mid = this.ownTrackMids.get(trackId);
    if (mid === undefined) {
      throw new NexusError('UNKNOWN_TRACK', `Track ${trackId} is not published by this client`);
    }
    this.request({ type: 'Unpublish', track_ids: [trackId] }, { kind: 'request' });
    this.ownTrackMids.delete(trackId);
    const track = this.localTrackByMid.get(mid);
    this.localTrackByMid.delete(mid);
    if (track) this.localTracks.delete(track.id);

    await this.detach(mid);
  }

  /** Stop sending on publish m-line `mid`; it stays usable for a later publish or subscription. */
  private async detach(mid: string): Promise<void> {
    const transceiver = this.pc?.getTransceivers().find((t) => t.mid === mid);
    if (transceiver) {
      await transceiver.sender.replaceTrack(null);
      // recvonly, not inactive: the SFU may reuse this m-line for a subscription
      transceiver.direction = 'recvonly';
    }
  }

  private async publishTrack(track: MediaStreamTrack, kind: string, content: string): Promise<void> {
    if (this.offerPending) {
      return new Promise(resolve => {
        this.pendingActions.push(() => this.publishTrack(track, kind, content).then(resolve));
      });
    }
    if (!this.pendingPublishes.has(track)) return; // failed or timed out while queued

    this.localTracks.set(track.id, track);
    
    this.ensurePeerConnection();

    // No addTrack here: it would reuse a receive-only transceiver left by an
    // existing subscription. The SFU's offer adds a recvonly m-line for this
    // track, and handleOffer attaches the track to it.
    this.unattachedTracks.push(track);

    // Declare only the new track; the SFU keeps earlier m-lines as negotiated
    this.offerPending = true;
    this.request(
      { type: 'Publish', kinds: [kind], contents: [content] },
      { kind: 'publish', track, offered: false },
    );
  }

  /** Send `msg` with a `Ping` behind it, so its replies end at the matching `Pong`. */
  private request(msg: SignalMessage, fence: Fence): void {
    this.signaling.send(msg);
    this.signaling.send({ type: 'Ping' });
    this.fences.push(fence);
  }

  /** Subscribe to tracks, in requests of at most `MAX_TRACKS_PER_REQUEST` ids. */
  async subscribe(trackIds: number[]): Promise<void> {
    for (const chunk of chunks(trackIds, MAX_TRACKS_PER_REQUEST)) {
      await this.subscribeChunk(chunk);
    }
  }

  private async subscribeChunk(trackIds: number[]): Promise<void> {
    if (this.offerPending) {
      return new Promise(resolve => {
        this.pendingActions.push(() => this.subscribeChunk(trackIds).then(resolve));
      });
    }

    this.request({ type: 'Subscribe', track_ids: trackIds }, { kind: 'subscribe' });
  }

  /** Unsubscribe from tracks, in requests of at most `MAX_TRACKS_PER_REQUEST` ids. */
  unsubscribe(trackIds: number[]): void {
    for (const chunk of chunks(trackIds, MAX_TRACKS_PER_REQUEST)) {
      this.request({ type: 'Unsubscribe', track_ids: chunk }, { kind: 'request' });
    }
  }

  attach(trackId: number, element: HTMLMediaElement): void {
    const stream = this.remoteTracks.get(trackId);
    if (stream) {
      element.srcObject = stream;
    }
  }

  /**
   * Leave the room. The SFU ends the session at `Leave` and ignores anything else on
   * that connection, so this also closes the peer connection and the socket. To
   * join again, call `connect()` and `join()`: a new participant id and session.
   */
  leave(): void {
    if (this.signaling.isConnected()) {
      this.signaling.send({ type: 'Leave' });
    }
    this.close();
  }

  /** Close the peer connection and the socket without `Leave` (the SFU cleans up). */
  close(): void {
    this.signaling.close();
    this.resetSession();
  }

  /** The peer connection's stats (SRTP cipher, ICE pair, per-track counters). */
  async getStats(): Promise<RTCStatsReport | null> {
    return this.pc ? this.pc.getStats() : null;
  }

  // Expose signaling methods for advanced usage
  send(msg: SignalMessage): void {
    this.signaling.send(msg);
  }

  off(event: string, handler: (...args: any[]) => void): void {
    super.off(event, handler);
    this.signaling.off(event, handler);
  }

  /** Forget everything tied to the SFU session; the next publish or offer starts anew. */
  private resetSession(): void {
    this.pc?.close();
    this.pc = null;
    this.participantId = null;
    this.roomId = null;
    this.localTracks.clear();
    this.remoteTracks.clear();
    this.trackIdByMid.clear();
    this.localTrackByMid.clear();
    this.ownTrackMids.clear();
    this.offerPending = false;
    this.unattachedTracks = [];
    this.pendingActions = [];
    this.fences = [];
    this.serverQueued = [];
    const err = new NexusError('CLOSED', 'Client closed');
    for (const pending of this.pendingPublishes.values()) {
      clearTimeout(pending.timer);
      pending.reject(err);
    }
    this.pendingPublishes.clear();
  }

  /**
   * A publish the SFU refused, or that timed out: reject it and undo its state, so the
   * track can be published again and queued requests go out.
   */
  private failPublish(track: MediaStreamTrack, err: NexusError): void {
    const pending = this.pendingPublishes.get(track);
    if (pending) {
      clearTimeout(pending.timer);
      this.pendingPublishes.delete(track);
      pending.reject(err);
    }
    this.localTracks.delete(track.id);
    this.forgetAnswerTrack(track);
    this.serverQueued = this.serverQueued.filter((t) => t !== track);
    const i = this.unattachedTracks.indexOf(track);
    if (i >= 0) {
      this.unattachedTracks.splice(i, 1);
      // Its offer will not come: stop holding back queued requests
      if (this.unattachedTracks.length === 0 && this.offerPending) {
        this.offerPending = false;
        this.runPendingActions();
      }
    }
    for (const [mid, t] of this.localTrackByMid) {
      if (t !== track) continue;
      this.localTrackByMid.delete(mid);
      this.detach(mid).catch((e) => console.error('Failed to detach track:', e));
    }
  }

  private forgetAnswerTrack(track: MediaStreamTrack): void {
    for (const fence of this.fences) {
      if (fence.kind === 'answer') fence.tracks = fence.tracks.filter((t) => t !== track);
    }
  }

  /**
   * An SFU error: the request it answers is the oldest one without a `Pong` yet.
   * An answer's replies are, in order: one result per published m-line, then the
   * outcome of a publish the SFU had queued (`serverQueued`). A subscription
   * renegotiation in between can also fail with `OFFER_FAILED` or `TOO_MANY_TRACKS`;
   * with a queued publish waiting, that error fails it too (it would build the same
   * offer).
   */
  private handleError(code: string, message: string): void {
    const head = this.fences[0];
    const err = new NexusError(code, message);
    if (head?.kind === 'publish' && PUBLISH_REFUSALS.has(code)) {
      this.failPublish(head.track, err);
    } else if (head?.kind === 'answer') {
      if (MLINE_REFUSALS.has(code) && head.tracks.length > 0) {
        this.failPublish(head.tracks[0], err);
      } else if (PUBLISH_REFUSALS.has(code)) {
        for (const track of [...this.serverQueued]) this.failPublish(track, err);
      }
    } else if (head?.kind === 'request') {
      head.onError?.(err);
    }
    this.emit('error', { code, message });
  }

  /** The replies to the oldest fenced request are complete. */
  private handlePong(): void {
    const fence = this.fences.shift();
    if (fence?.kind === 'publish' && !fence.offered && this.pendingPublishes.has(fence.track)) {
      // Neither an offer nor a refusal: the SFU queued it behind its outstanding offer
      this.serverQueued.push(fence.track);
    } else if (fence?.kind === 'answer') {
      // Neither registered nor refused (e.g. the answer rejected the m-line)
      for (const track of fence.tracks) {
        this.failPublish(track, new NexusError('NOT_REGISTERED', 'The SFU did not register the track'));
      }
    }
  }

  private setupSignaling(): void {
    this.signaling.on('message', (msg: SignalMessage) => {
      this.handleMessage(msg);
      // Also emit raw message for advanced usage
      this.emit('message', msg);
    });

    this.signaling.on('disconnected', (data) => {
      // No Pong comes from a closed connection. Pings still queued would be sent on the
      // next one and answer requests they do not belong to.
      this.fences = [];
      this.serverQueued = [];
      this.signaling.dropQueued((m) => m.type === 'Ping');
      this.emit('disconnected', data);
    });

    this.signaling.on('keepalive', () => {
      this.fences.push({ kind: 'keepalive' });
    });

    this.signaling.on('reconnecting', (data) => {
      this.emit('reconnecting', data);
    });
  }

  private setupPeerConnection(): void {
    if (!this.pc) return;

    this.pc.onicecandidate = (event) => {
      if (event.candidate) {
        this.signaling.send({
          type: 'IceCandidate',
          candidate: event.candidate.candidate,
          sdp_mid: event.candidate.sdpMid ?? undefined,
          sdp_mline_index: event.candidate.sdpMLineIndex ?? undefined,
        });
      } else {
        this.signaling.send({ type: 'EndOfCandidates' });
      }
    };

    this.pc.ontrack = (event) => {
      // The SFU's offer may carry no msid, leaving event.streams empty
      const stream = event.streams[0] ?? new MediaStream([event.track]);
      const mid = event.transceiver.mid;
      const trackId = mid === null ? undefined : this.trackIdByMid.get(mid);
      if (trackId === undefined) {
        console.warn(`Received media on m-line ${mid} with no subscribed track`);
        return;
      }
      this.remoteTracks.set(trackId, stream);
      this.emit('trackSubscribed', { trackId, track: event.track, stream });
    };

    this.pc.onconnectionstatechange = () => {
      console.log('PC state:', this.pc?.connectionState);
    };
  }

  private async handleMessage(msg: SignalMessage): Promise<void> {
    switch (msg.type) {
      case 'Offer':
        // Synchronously, before the Pong that ends the Publish's replies
        if (this.fences[0]?.kind === 'publish') this.fences[0].offered = true;
        this.updateTrackMids(msg.tracks ?? []);
        await this.handleOffer(msg.sdp);
        break;
      case 'IceCandidate':
        await this.handleIceCandidate(msg);
        break;
      case 'TrackPublished':
        this.emit('trackPublished', {
          publisherId: msg.publisher_id,
          trackId: msg.track_id,
          kind: msg.kind,
          content: msg.content,
        });
        break;
      case 'Published':
        this.handlePublished(msg.track_id, msg.mid);
        break;
      case 'TrackUnpublished':
        this.remoteTracks.delete(msg.track_id);
        this.emit('trackUnpublished', { trackId: msg.track_id });
        break;
      case 'ParticipantJoined':
        this.emit('participantJoined', { participantId: msg.participant_id, name: msg.name });
        break;
      case 'ParticipantLeft':
        this.emit('participantLeft', { participantId: msg.participant_id });
        break;
      case 'ServerShutdown':
        this.emit('serverShutdown', { reason: msg.reason, drainSeconds: msg.drain_seconds });
        break;
      case 'Pong':
        this.handlePong();
        break;
      case 'Error':
        this.handleError(msg.code, msg.message);
        break;
    }
  }

  /** The SFU registered one of our tracks from the answer on m-line `mid`. */
  private handlePublished(trackId: number, mid: string): void {
    this.ownTrackMids.set(trackId, mid);
    const track = this.localTrackByMid.get(mid);
    if (!track) {
      // Its publish failed here (timed out) but the SFU registered it anyway. The app
      // gets the id so it can `unpublish` it; nothing is sent on the m-line.
      this.emit('lateTrackPublished', { trackId, mid });
      return;
    }
    this.forgetAnswerTrack(track);
    const pending = this.pendingPublishes.get(track);
    if (pending) {
      clearTimeout(pending.timer);
      this.pendingPublishes.delete(track);
      pending.resolve(trackId);
    }
    this.emit('localTrackPublished', { trackId, track });
  }

  /**
   * Record which track each m-line carries. Runs before the offer is applied
   * because `track` events fire during setRemoteDescription.
   */
  private updateTrackMids(tracks: OfferTrack[]): void {
    const next = new Map(tracks.map((t) => [t.mid, t.track_id] as [string, number]));
    // An m-line that stopped carrying a track (unsubscribed or reassigned)
    for (const [mid, trackId] of this.trackIdByMid) {
      if (next.get(mid) !== trackId) this.remoteTracks.delete(trackId);
    }
    this.trackIdByMid = next;
  }

  private ensurePeerConnection(): RTCPeerConnection {
    if (!this.pc) {
      this.pc = new RTCPeerConnection({ iceServers: this.iceServers });
      this.setupPeerConnection();
    }
    return this.pc;
  }

  private async handleOffer(sdp: string): Promise<void> {
    const pc = this.ensurePeerConnection();
    await pc.setRemoteDescription({ type: 'offer', sdp });
    const attached = await this.attachPendingTracks(sdp);
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);

    this.request({ type: 'Answer', sdp: answer.sdp! }, { kind: 'answer', tracks: attached });
    this.offerPending = false;
    this.runPendingActions();
  }

  private runPendingActions(): void {
    while (this.pendingActions.length > 0) {
      const action = this.pendingActions.shift()!;
      action();
    }
  }

  /**
   * Send each pending local track on a transceiver the offer created for one of
   * the SFU's recvonly (publish) m-lines, matching by kind.
   */
  private async attachPendingTracks(offerSdp: string): Promise<MediaStreamTrack[]> {
    const attached: MediaStreamTrack[] = [];
    if (!this.pc || this.unattachedTracks.length === 0) return attached;

    const publishMids = new Set<string>();
    for (const section of offerSdp.split(/\r?\nm=/).slice(1)) {
      const mid = /\r?\na=mid:(\S+)/.exec(section)?.[1];
      if (mid && /\r?\na=recvonly/.test(section)) publishMids.add(mid);
    }

    for (const transceiver of this.pc.getTransceivers()) {
      if (!transceiver.mid || !publishMids.has(transceiver.mid) || transceiver.sender.track) continue;
      const i = this.unattachedTracks.findIndex((t) => t.kind === transceiver.receiver.track.kind);
      if (i < 0) continue;
      const [track] = this.unattachedTracks.splice(i, 1);
      transceiver.direction = 'sendonly';
      await transceiver.sender.replaceTrack(track);
      this.localTrackByMid.set(transceiver.mid, track);
      attached.push(track);
    }
    this.serverQueued = this.serverQueued.filter((t) => !attached.includes(t));
    return attached;
  }

  private async handleIceCandidate(msg: SignalMessage & { type: 'IceCandidate' }): Promise<void> {
    if (!this.pc) return;
    
    try {
      await this.pc.addIceCandidate(new RTCIceCandidate({
        candidate: msg.candidate,
        sdpMid: msg.sdp_mid,
        sdpMLineIndex: msg.sdp_mline_index,
      }));
    } catch (e) {
      console.error('Failed to add ICE candidate:', e);
    }
  }
}

/** `items` in consecutive slices of at most `size`. */
function chunks<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) {
    out.push(items.slice(i, i + size));
  }
  return out;
}
