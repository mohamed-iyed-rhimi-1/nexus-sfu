// ============================================================================
// Nexus SDK — Publisher
// Manages local media publishing: camera, microphone, screen share.
// Single RTCPeerConnection, unified plan SDP negotiation.
// ============================================================================

import type { Signaling } from './signaling.js';
import type { AnswerReceivedMsg, ContentType, SignalMessage } from './types.js';

/** A published local track. */
export interface LocalTrack {
  trackId: number;
  sender: RTCRtpSender;
  mediaTrack: MediaStreamTrack;
  content: ContentType;
}

/** Simulcast encoding config for camera video. */
const CAMERA_ENCODINGS: RTCRtpEncodingParameters[] = [
  { rid: 'q', maxBitrate: 100_000, scaleResolutionDownBy: 4 },
  { rid: 'h', maxBitrate: 500_000, scaleResolutionDownBy: 2 },
  { rid: 'f', maxBitrate: 1_500_000 },
];

/** Single high-quality encoding for screen share. */
const SCREEN_ENCODINGS: RTCRtpEncodingParameters[] = [
  { maxBitrate: 3_000_000 },
];

export class Publisher {
  private pc: RTCPeerConnection;
  private signaling: Signaling;
  private localTracks = new Map<string, LocalTrack>(); // keyed by MediaStreamTrack.id
  private nextTrackId = 1;
  private negotiating = false;
  private needsRenegotiation = false;

  constructor(
    signaling: Signaling,
    _participantIdFn: () => number,
    rtcConfig?: RTCConfiguration,
  ) {
    this.signaling = signaling;
    this.pc = new RTCPeerConnection(rtcConfig);

    this.pc.onicecandidate = (ev) => {
      if (ev.candidate) {
        this.signaling.send({
          type: 'IceCandidate',
          target_participant_id: 0, // SFU is the target
          candidate: ev.candidate.candidate,
          sdp_mid: ev.candidate.sdpMid ?? undefined,
          sdp_mline_index: ev.candidate.sdpMLineIndex ?? undefined,
        });
      } else {
        this.signaling.send({ type: 'EndOfCandidates' });
      }
    };
  }

  /** Publish camera video. Returns the local track info. */
  async publishCamera(
    constraints?: MediaTrackConstraints,
  ): Promise<LocalTrack> {
    const stream = await navigator.mediaDevices.getUserMedia({
      video: constraints ?? { width: 1280, height: 720, frameRate: 30 },
      audio: false,
    });
    return this.addTrack(stream.getVideoTracks()[0], 'camera', CAMERA_ENCODINGS);
  }

  /** Publish microphone audio. */
  async publishMicrophone(
    constraints?: MediaTrackConstraints,
  ): Promise<LocalTrack> {
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: constraints ?? true,
      video: false,
    });
    return this.addTrack(stream.getAudioTracks()[0], 'audio', undefined);
  }

  /** Publish screen share. Single high-quality layer, no simulcast. */
  async publishScreen(
    constraints?: DisplayMediaStreamOptions,
  ): Promise<LocalTrack> {
    const stream = await navigator.mediaDevices.getDisplayMedia(
      constraints ?? { video: { frameRate: 15 } },
    );
    const track = stream.getVideoTracks()[0];

    // When user stops sharing via browser UI
    track.onended = () => {
      this.unpublish(track.id);
    };

    return this.addTrack(track, 'screen', SCREEN_ENCODINGS);
  }

  /** Remove a published track by MediaStreamTrack.id. */
  async unpublish(mediaTrackId: string): Promise<void> {
    const local = this.localTracks.get(mediaTrackId);
    if (!local) return;

    local.mediaTrack.stop();
    this.pc.removeTrack(local.sender);
    this.localTracks.delete(mediaTrackId);
    await this.renegotiate();
  }

  /** Handle incoming signaling messages (Answer, ICE). Returns true if consumed. */
  handleMessage(msg: SignalMessage): boolean {
    switch (msg.type) {
      case 'AnswerReceived':
        this.handleAnswer(msg);
        return true;
      default:
        return false;
    }
  }

  /** Close the publisher peer connection. */
  close(): void {
    for (const local of this.localTracks.values()) {
      local.mediaTrack.stop();
    }
    this.localTracks.clear();
    this.pc.close();
  }

  /** Get all published tracks. */
  get tracks(): LocalTrack[] {
    return [...this.localTracks.values()];
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private async addTrack(
    mediaTrack: MediaStreamTrack,
    content: ContentType,
    encodings?: RTCRtpEncodingParameters[],
  ): Promise<LocalTrack> {
    const stream = new MediaStream([mediaTrack]);
    let sender: RTCRtpSender;

    if (encodings && mediaTrack.kind === 'video') {
      const transceiver = this.pc.addTransceiver(mediaTrack, {
        direction: 'sendonly',
        streams: [stream],
        sendEncodings: encodings,
      });
      sender = transceiver.sender;
    } else {
      sender = this.pc.addTrack(mediaTrack, stream);
    }

    const trackId = this.nextTrackId++;
    const local: LocalTrack = { trackId, sender, mediaTrack, content };
    this.localTracks.set(mediaTrack.id, local);

    await this.renegotiate();

    // Tell SFU this is a screen share (or camera/audio)
    if (content === 'screen') {
      this.signaling.send({
        type: 'SetContent',
        track_id: trackId,
        content: 'screen',
      });
    }

    return local;
  }

  private async renegotiate(): Promise<void> {
    if (this.negotiating) {
      this.needsRenegotiation = true;
      return;
    }
    this.negotiating = true;

    try {
      const offer = await this.pc.createOffer();
      await this.pc.setLocalDescription(offer);

      const answer = await this.signaling.request<AnswerReceivedMsg>(
        {
          type: 'Offer',
          target_participant_id: undefined,
          sdp: offer.sdp!,
        },
        'AnswerReceived',
      );

      await this.pc.setRemoteDescription({
        type: 'answer',
        sdp: answer.sdp,
      });
    } finally {
      this.negotiating = false;
      if (this.needsRenegotiation) {
        this.needsRenegotiation = false;
        await this.renegotiate();
      }
    }
  }

  private async handleAnswer(msg: AnswerReceivedMsg): Promise<void> {
    if (this.pc.signalingState === 'have-local-offer') {
      await this.pc.setRemoteDescription({ type: 'answer', sdp: msg.sdp });
    }
  }
}
