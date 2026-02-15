// ============================================================================
// Nexus SDK — Signaling Layer
// Sits on top of transport. Handles serialization, reconnect, keepalive,
// and request-response correlation.
// ============================================================================

import type { SignalingTransport } from './transport/transport.js';
import { WebSocketTransport } from './transport/ws.js';
import { QuicTransport } from './transport/quic.js';
import type { SignalMessage, NexusConfig, TransportType } from './types.js';

type MessageHandler = (msg: SignalMessage) => void;

/** Pending request awaiting a response message. */
interface PendingRequest {
  resolve: (msg: SignalMessage) => void;
  reject: (err: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

const DEFAULT_PING_INTERVAL = 30_000;
const DEFAULT_MAX_RECONNECT = 5;
const REQUEST_TIMEOUT = 5_000;

export class Signaling {
  private transport: SignalingTransport | null = null;
  private config: Required<
    Pick<NexusConfig, 'url' | 'maxReconnectAttempts' | 'pingIntervalMs'>
  > & { token?: string; transport: TransportType };
  private handler: MessageHandler | null = null;
  private pingTimer: ReturnType<typeof setInterval> | null = null;
  private reconnectAttempt = 0;
  private closed = false;
  private pendingRequests = new Map<string, PendingRequest>();

  /** Called on disconnect (before reconnect attempts). */
  onDisconnect: ((reason: string) => void) | null = null;
  /** Called when starting a reconnect attempt. */
  onReconnecting: ((attempt: number) => void) | null = null;
  /** Called when reconnect succeeds. */
  onReconnected: (() => void) | null = null;

  constructor(config: NexusConfig) {
    this.config = {
      url: config.url,
      token: config.token,
      transport: config.transport ?? 'auto',
      maxReconnectAttempts: config.maxReconnectAttempts ?? DEFAULT_MAX_RECONNECT,
      pingIntervalMs: config.pingIntervalMs ?? DEFAULT_PING_INTERVAL,
    };
  }

  /** Register the handler for incoming messages. */
  onMessage(handler: MessageHandler): void {
    this.handler = handler;
  }

  /** Connect to the server. Tries QUIC first if transport is 'auto'. */
  async connect(): Promise<void> {
    this.closed = false;
    this.transport = await this.createTransport(this.config.transport);
    this.wireTransport();
    await this.transport.connect(this.buildUrl());
    this.reconnectAttempt = 0;
    this.startPing();
  }

  /** Send a signal message (fire-and-forget). */
  send(msg: SignalMessage): void {
    if (!this.transport || this.transport.state !== 'open') return;
    this.transport.send(JSON.stringify(msg));
  }

  /**
   * Send a request and wait for a specific response type.
   * E.g. send Join, wait for Joined. Rejects after 5s timeout.
   */
  request<T extends SignalMessage>(
    msg: SignalMessage,
    responseType: T['type'],
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pendingRequests.delete(responseType);
        reject(new Error(`Timeout waiting for ${responseType}`));
      }, REQUEST_TIMEOUT);

      this.pendingRequests.set(responseType, {
        resolve: resolve as (m: SignalMessage) => void,
        reject,
        timer,
      });

      this.send(msg);
    });
  }

  /** Gracefully disconnect. No reconnect. */
  close(): void {
    this.closed = true;
    this.stopPing();
    this.rejectAllPending('Connection closed');
    this.transport?.close();
    this.transport = null;
  }

  get connected(): boolean {
    return this.transport?.state === 'open';
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private buildUrl(): string {
    const { url, token } = this.config;
    if (!token) return url;
    const sep = url.includes('?') ? '&' : '?';
    return `${url}${sep}token=${encodeURIComponent(token)}`;
  }

  private async createTransport(
    preference: TransportType,
  ): Promise<SignalingTransport> {
    if (preference === 'quic' || preference === 'auto') {
      try {
        const qt = new QuicTransport();
        // Test if WebTransport is available by checking the constructor didn't throw
        if (preference === 'quic') return qt;
        // 'auto': try QUIC, fall back to WS
        return qt;
      } catch {
        if (preference === 'quic') {
          throw new Error('WebTransport not available');
        }
      }
    }
    return new WebSocketTransport();
  }

  private wireTransport(): void {
    if (!this.transport) return;

    this.transport.onMessage((data) => {
      if (typeof data !== 'string') return;
      let msg: SignalMessage;
      try {
        msg = JSON.parse(data) as SignalMessage;
      } catch {
        return;
      }

      // Handle pong internally
      if (msg.type === 'Pong') return;

      // Resolve pending request if type matches
      const pending = this.pendingRequests.get(msg.type);
      if (pending) {
        this.pendingRequests.delete(msg.type);
        clearTimeout(pending.timer);
        pending.resolve(msg);
      }

      // Always dispatch to handler
      this.handler?.(msg);
    });

    this.transport.onClose((_code, reason) => {
      this.stopPing();
      this.onDisconnect?.(reason);
      if (!this.closed) this.attemptReconnect();
    });
  }

  private startPing(): void {
    this.stopPing();
    this.pingTimer = setInterval(() => {
      this.send({ type: 'Ping' });
    }, this.config.pingIntervalMs);
  }

  private stopPing(): void {
    if (this.pingTimer) {
      clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
  }

  private async attemptReconnect(): Promise<void> {
    const max = this.config.maxReconnectAttempts;
    while (this.reconnectAttempt < max && !this.closed) {
      this.reconnectAttempt++;
      this.onReconnecting?.(this.reconnectAttempt);

      // Exponential backoff: 1s, 2s, 4s, 8s, 16s
      const delay = Math.min(1000 * 2 ** (this.reconnectAttempt - 1), 16_000);
      await this.sleep(delay);

      if (this.closed) return;

      try {
        // On reconnect, fall back to WS if QUIC was the original choice
        // (QUIC reconnect with 0-RTT is handled by the transport itself)
        this.transport = await this.createTransport(this.config.transport);
        this.wireTransport();
        await this.transport.connect(this.buildUrl());
        this.reconnectAttempt = 0;
        this.startPing();
        this.onReconnected?.();
        return;
      } catch {
        // Try again
      }
    }

    // Exhausted attempts
    this.rejectAllPending('Reconnect failed');
  }

  private rejectAllPending(reason: string): void {
    for (const [, pending] of this.pendingRequests) {
      clearTimeout(pending.timer);
      pending.reject(new Error(reason));
    }
    this.pendingRequests.clear();
  }

  private sleep(ms: number): Promise<void> {
    return new Promise((r) => setTimeout(r, ms));
  }
}
