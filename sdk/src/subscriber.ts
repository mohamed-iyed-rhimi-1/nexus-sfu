// ============================================================================
// Nexus SDK — Subscriber
// Manages remote track subscriptions and attaching to DOM elements.
// ============================================================================

import type { Signaling } from './signaling.js';
import type { SignalMessage, SubscribedMsg } from './types.js';

/** A subscribed remote track. */
export interface RemoteSubscription {
  trackId: number;
  subscriberId: number;
  track: MediaStreamTrack | null;
  stream: MediaStream | null;
  element: HTMLMediaElement | null;
}

export class Subscriber {
  private pc: RTCPeerConnection;
  private signaling: Signaling;
  private subscriptions = new Map<number, RemoteSubscription>(); // keyed by trackId
  /** Pending track IDs waiting for ontrack event. */
  private pendingTracks = new Map<string, number>(); // mid → trackId

  /** Called when a remote track is received. */
  onTrackReceived:
    | ((trackId: number, track: MediaStreamTrack, stream: MediaStream) => void)
    | null = null;

  constructor(
    signaling: Signaling,
    rtcConfig?: RTCConfiguration,
  ) {
    this.signaling = signaling;
    this.pc = new RTCPeerConnection(rtcConfig);

    this.pc.ontrack = (ev) => {
      this.handleOnTrack(ev);
    };

    this.pc.onicecandidate = (ev) => {
      if (ev.candidate) {
        this.signaling.send({
          type: 'IceCandidate',
          target_participant_id: 0,
          candidate: ev.candidate.candidate,
          sdp_mid: ev.candidate.sdpMid ?? undefined,
          sdp_mline_index: ev.candidate.sdpMLineIndex ?? undefined,
        });
      }
    };
  }

  /** Subscribe to a remote track. */
  async subscribe(trackId: number): Promise<RemoteSubscription> {
    const resp = await this.signaling.request<SubscribedMsg>(
      { type: 'Subscribe', track_id: trackId },
      'Subscribed',
    );

    const sub: RemoteSubscription = {
      trackId,
      subscriberId: resp.subscriber_id,
      track: null,
      stream: null,
      element: null,
    };
    this.subscriptions.set(trackId, sub);
    return sub;
  }

  /** Unsubscribe from a remote track. */
  unsubscribe(trackId: number): void {
    const sub = this.subscriptions.get(trackId);
    if (!sub) return;

    this.detach(trackId);
    this.signaling.send({ type: 'Unsubscribe', track_id: trackId });
    this.subscriptions.delete(trackId);
  }

  /** Attach a subscribed track to a DOM element. */
  attach(trackId: number, element: HTMLMediaElement): boolean {
    const sub = this.subscriptions.get(trackId);
    if (!sub?.stream) return false;

    element.srcObject = sub.stream;
    element.autoplay = true;
    if (element instanceof HTMLVideoElement) {
      element.playsInline = true;
    }
    sub.element = element;
    return true;
  }

  /** Detach a track from its DOM element. */
  detach(trackId: number): void {
    const sub = this.subscriptions.get(trackId);
    if (!sub?.element) return;
    sub.element.srcObject = null;
    sub.element = null;
  }

  /** Get a subscription by track ID. */
  get(trackId: number): RemoteSubscription | undefined {
    return this.subscriptions.get(trackId);
  }

  /** Handle incoming signaling messages (Offer from SFU, ICE). */
  async handleMessage(msg: SignalMessage): Promise<boolean> {
    switch (msg.type) {
      case 'OfferReceived': {
        // SFU sends an offer when adding subscriber tracks
        await this.pc.setRemoteDescription({ type: 'offer', sdp: msg.sdp });
        const answer = await this.pc.createAnswer();
        await this.pc.setLocalDescription(answer);
        this.signaling.send({
          type: 'Answer',
          target_participant_id: msg.from_participant_id,
          sdp: answer.sdp!,
        });
        return true;
      }
      default:
        return false;
    }
  }

  /** Close the subscriber peer connection. */
  close(): void {
    for (const sub of this.subscriptions.values()) {
      if (sub.element) sub.element.srcObject = null;
    }
    this.subscriptions.clear();
    this.pendingTracks.clear();
    this.pc.close();
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private handleOnTrack(ev: RTCTrackEvent): void {
    const track = ev.track;
    const stream = ev.streams[0] ?? new MediaStream([track]);

    // Match to a subscription. Try by mid first, then find first unmatched.
    let matched: RemoteSubscription | undefined;

    // Find first subscription without a track
    for (const sub of this.subscriptions.values()) {
      if (!sub.track) {
        matched = sub;
        break;
      }
    }

    if (matched) {
      matched.track = track;
      matched.stream = stream;
      this.onTrackReceived?.(matched.trackId, track, stream);

      // Auto-attach if element was set before track arrived
      if (matched.element) {
        matched.element.srcObject = stream;
      }
    }
  }
}
