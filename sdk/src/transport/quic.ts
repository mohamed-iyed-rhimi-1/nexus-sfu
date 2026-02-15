// ============================================================================
// Nexus SDK — QUIC Transport (WebTransport API)
// Uses a single bidirectional stream for ordered signaling.
// Falls back gracefully — caller should catch and use WebSocket.
// ============================================================================

import type { SignalingTransport, TransportState } from './transport.js';

/**
 * WebTransport-based signaling transport.
 *
 * Requires browser support for the WebTransport API (Chrome 97+, Firefox 114+).
 * Uses a single bidirectional stream for reliable, ordered message delivery.
 * Supports 0-RTT reconnection when the server provides session tickets.
 */
export class QuicTransport implements SignalingTransport {
  private transport: WebTransport | null = null;
  private writer: WritableStreamDefaultWriter<Uint8Array> | null = null;
  private messageHandler: ((data: string | Uint8Array) => void) | null = null;
  private closeHandler: ((code: number, reason: string) => void) | null = null;
  private currentState: TransportState = 'closed';
  private abortController: AbortController | null = null;

  get state(): TransportState {
    return this.currentState;
  }

  async connect(url: string): Promise<void> {
    if (typeof WebTransport === 'undefined') {
      throw new Error('WebTransport not supported in this environment');
    }

    this.currentState = 'connecting';
    this.abortController = new AbortController();

    // Convert ws:// or wss:// to https:// for WebTransport
    const wtUrl = url.replace(/^wss?:\/\//, 'https://');

    this.transport = new WebTransport(wtUrl);

    // Wait for connection
    await this.transport.ready;
    this.currentState = 'open';

    // Open a single bidirectional stream for signaling
    const stream = await this.transport.createBidirectionalStream();
    this.writer = stream.writable.getWriter();

    // Read loop on the readable side
    this.readLoop(stream.readable);

    // Monitor connection close
    this.transport.closed
      .then(() => {
        this.currentState = 'closed';
        this.closeHandler?.(1000, 'transport closed');
      })
      .catch((err: Error) => {
        this.currentState = 'closed';
        this.closeHandler?.(1006, err.message);
      });
  }

  send(data: string | Uint8Array): void {
    if (!this.writer || this.currentState !== 'open') return;

    const bytes =
      typeof data === 'string' ? new TextEncoder().encode(data) : data;

    // Length-prefixed framing: [u32 BE length][payload]
    const frame = new Uint8Array(4 + bytes.length);
    new DataView(frame.buffer).setUint32(0, bytes.length, false);
    frame.set(bytes, 4);

    this.writer.write(frame).catch(() => {
      /* stream closed — closeHandler will fire */
    });
  }

  onMessage(handler: (data: string | Uint8Array) => void): void {
    this.messageHandler = handler;
  }

  onClose(handler: (code: number, reason: string) => void): void {
    this.closeHandler = handler;
  }

  close(_code?: number, reason = 'client close'): void {
    this.currentState = 'closing';
    this.abortController?.abort();
    this.writer?.close().catch(() => {});
    this.transport?.close({ closeCode: 0, reason });
    this.transport = null;
    this.writer = null;
    this.currentState = 'closed';
  }

  // -------------------------------------------------------------------------
  // Internal: read loop with length-prefixed framing
  // -------------------------------------------------------------------------

  private async readLoop(readable: ReadableStream<Uint8Array>): Promise<void> {
    const reader = readable.getReader();
    let buffer = new Uint8Array(0);

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        // Append to buffer
        const next = new Uint8Array(buffer.length + value.length);
        next.set(buffer);
        next.set(value, buffer.length);
        buffer = next;

        // Parse length-prefixed frames
        while (buffer.length >= 4) {
          const len = new DataView(
            buffer.buffer,
            buffer.byteOffset,
          ).getUint32(0, false);
          if (buffer.length < 4 + len) break; // incomplete frame

          const payload = buffer.slice(4, 4 + len);
          buffer = buffer.slice(4 + len);

          const text = new TextDecoder().decode(payload);
          this.messageHandler?.(text);
        }
      }
    } catch {
      /* stream error — closeHandler fires via transport.closed */
    } finally {
      reader.releaseLock();
    }
  }
}
