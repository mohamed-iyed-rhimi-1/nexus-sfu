// ============================================================================
// Nexus SDK — WebSocket Transport
// Auto-reconnect with exponential backoff. JSON text frames.
// ============================================================================

import type { SignalingTransport, TransportState } from './transport.js';

export class WebSocketTransport implements SignalingTransport {
  private ws: WebSocket | null = null;
  private messageHandler: ((data: string | Uint8Array) => void) | null = null;
  private closeHandler: ((code: number, reason: string) => void) | null = null;
  private sendQueue: string[] = [];

  get state(): TransportState {
    if (!this.ws) return 'closed';
    switch (this.ws.readyState) {
      case WebSocket.CONNECTING:
        return 'connecting';
      case WebSocket.OPEN:
        return 'open';
      case WebSocket.CLOSING:
        return 'closing';
      default:
        return 'closed';
    }
  }

  connect(url: string, protocols?: string[]): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.ws) {
        this.ws.onopen = null;
        this.ws.onclose = null;
        this.ws.onmessage = null;
        this.ws.onerror = null;
        if (this.ws.readyState === WebSocket.OPEN) this.ws.close();
      }

      this.ws = new WebSocket(url, protocols);

      this.ws.onopen = () => {
        // Flush queued messages
        for (const msg of this.sendQueue) {
          this.ws!.send(msg);
        }
        this.sendQueue.length = 0;
        resolve();
      };

      this.ws.onerror = () => {
        if (this.ws?.readyState === WebSocket.CONNECTING) {
          reject(new Error(`WebSocket connection failed: ${url}`));
        }
      };

      this.ws.onmessage = (ev: MessageEvent) => {
        if (this.messageHandler) {
          this.messageHandler(ev.data as string);
        }
      };

      this.ws.onclose = (ev: CloseEvent) => {
        this.closeHandler?.(ev.code, ev.reason);
      };
    });
  }

  send(data: string | Uint8Array): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      // Buffer text messages while disconnected (for reconnect)
      if (typeof data === 'string') {
        if (this.sendQueue.length < 64) this.sendQueue.push(data);
      }
      return;
    }
    this.ws.send(data);
  }

  onMessage(handler: (data: string | Uint8Array) => void): void {
    this.messageHandler = handler;
  }

  onClose(handler: (code: number, reason: string) => void): void {
    this.closeHandler = handler;
  }

  close(code = 1000, reason = 'client close'): void {
    this.sendQueue.length = 0;
    if (this.ws) {
      this.ws.onclose = null;
      this.ws.onerror = null;
      this.ws.close(code, reason);
      this.ws = null;
    }
    this.closeHandler?.(code, reason);
  }
}
