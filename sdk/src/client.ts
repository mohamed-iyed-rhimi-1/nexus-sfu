import { SignalingTransport } from './signaling';
import { SignalMessage, TrackInfo } from './messages';
import { EventEmitter } from './events';
import { NexusError } from './errors';

export interface NexusClientConfig {
  url: string;
}

export class NexusClient extends EventEmitter {
  private signaling: SignalingTransport;
  private pc: RTCPeerConnection | null = null;
  private participantId: number | null = null;
  private roomId: number | null = null;
  private localTracks = new Map<string, MediaStreamTrack>();
  private remoteTracks = new Map<number, MediaStream>();
  private offerPending = false;
  private pendingActions: (() => void)[] = [];

  constructor(config: NexusClientConfig) {
    super();
    this.signaling = new SignalingTransport(config.url);
    this.setupSignaling();
  }

  async connect(): Promise<void> {
    await this.signaling.connect();
    this.emit('connected');
  }

  async join(roomId: number, name: string): Promise<{ participantId: number; participants: any[]; tracks: TrackInfo[] }> {
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new NexusError('TIMEOUT', 'Join timeout')), 10000);
      
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
        } else if (msg.type === 'Error') {
          clearTimeout(timeout);
          this.signaling.off('message', handler);
          reject(new NexusError(msg.code, msg.message));
        }
      };
      
      this.signaling.on('message', handler);
      this.signaling.send({ type: 'Join', room_id: roomId, participant_name: name });
    });
  }

  async publishCamera(): Promise<MediaStreamTrack> {
    const stream = await navigator.mediaDevices.getUserMedia({ video: true });
    const track = stream.getVideoTracks()[0];
    await this.publishTrack(track, 'video', 'camera');
    return track;
  }

  async publishMicrophone(): Promise<MediaStreamTrack> {
    const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
    const track = stream.getAudioTracks()[0];
    await this.publishTrack(track, 'audio', 'audio');
    return track;
  }

  async publishScreen(): Promise<MediaStreamTrack> {
    const stream = await navigator.mediaDevices.getDisplayMedia({ video: true });
    const track = stream.getVideoTracks()[0];
    await this.publishTrack(track, 'video', 'screen');
    return track;
  }

  private async publishTrack(track: MediaStreamTrack, kind: string, content: string): Promise<void> {
    if (this.offerPending) {
      return new Promise(resolve => {
        this.pendingActions.push(() => this.publishTrack(track, kind, content).then(resolve));
      });
    }

    this.localTracks.set(track.id, track);
    
    // Create PC if needed
    if (!this.pc) {
      this.pc = new RTCPeerConnection({
        iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
      });
      this.setupPeerConnection();
    }

    // Add track to PC
    this.pc.addTrack(track);

    // Send Publish intent → SFU will send Offer
    const kinds: string[] = [];
    const contents: string[] = [];
    this.localTracks.forEach((t) => {
      kinds.push(t.kind);
      contents.push(content); // Simplified: use same content for all
    });

    this.signaling.send({ type: 'Publish', kinds, contents });
    this.offerPending = true;
  }

  async subscribe(trackIds: number[]): Promise<void> {
    if (this.offerPending) {
      return new Promise(resolve => {
        this.pendingActions.push(() => this.subscribe(trackIds).then(resolve));
      });
    }

    this.signaling.send({ type: 'Subscribe', track_ids: trackIds });
  }

  attach(trackId: number, element: HTMLMediaElement): void {
    const stream = this.remoteTracks.get(trackId);
    if (stream) {
      element.srcObject = stream;
    }
  }

  close(): void {
    this.pc?.close();
    this.signaling.close();
    this.localTracks.clear();
    this.remoteTracks.clear();
  }

  // Expose signaling methods for advanced usage
  send(msg: SignalMessage): void {
    this.signaling.send(msg);
  }

  off(event: string, handler: (...args: any[]) => void): void {
    this.signaling.off(event, handler);
  }

  private setupSignaling(): void {
    this.signaling.on('message', (msg: SignalMessage) => {
      this.handleMessage(msg);
      // Also emit raw message for advanced usage
      this.emit('message', msg);
    });

    this.signaling.on('disconnected', (data) => {
      this.emit('disconnected', data);
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
      const stream = event.streams[0];
      // Extract track_id from stream or transceiver (simplified)
      const trackId = Date.now(); // TODO: proper track_id mapping
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
      case 'TrackUnpublished':
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
      case 'Error':
        this.emit('error', { code: msg.code, message: msg.message });
        break;
    }
  }

  private async handleOffer(sdp: string): Promise<void> {
    if (!this.pc) {
      this.pc = new RTCPeerConnection({
        iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],
      });
      this.setupPeerConnection();
    }

    await this.pc.setRemoteDescription({ type: 'offer', sdp });
    const answer = await this.pc.createAnswer();
    await this.pc.setLocalDescription(answer);
    
    this.signaling.send({ type: 'Answer', sdp: answer.sdp! });
    this.offerPending = false;

    // Process queued actions
    while (this.pendingActions.length > 0) {
      const action = this.pendingActions.shift()!;
      action();
    }
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
