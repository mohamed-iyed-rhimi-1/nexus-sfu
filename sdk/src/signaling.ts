import { SignalMessage } from './messages';
import { EventEmitter } from './events';
import { NexusError } from './errors';

/** JWT for the auth handshake, or a function returning one (called on every (re)connect). */
export type TokenSource = string | (() => string | Promise<string>);

/** The SFU drops connections that don't authenticate within 10s. */
const AUTH_TIMEOUT_MS = 10000;

export class SignalingTransport extends EventEmitter {
  private ws: WebSocket | null = null;
  private reconnectAttempt = 0;
  private maxReconnectDelay = 30000;
  private messageQueue: SignalMessage[] = [];
  private pingInterval: number | null = null;
  private authenticated = false;
  /** Set by close() or an auth rejection; suppresses automatic reconnects. */
  private stopped = false;

  constructor(private url: string, private token?: TokenSource) {
    super();
  }

  connect(): Promise<void> {
    this.stopped = false;
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(this.url);
      this.ws = ws;
      this.authenticated = false;
      let settled = false;
      const fail = (err: NexusError) => {
        if (!settled) {
          settled = true;
          reject(err);
        }
      };

      ws.onopen = async () => {
        // First message must be {"type":"auth","token":...}; the reply is raw
        // JSON ({"type":"auth_ok"} or {"type":"error"}), not a SignalMessage.
        try {
          const token = await this.resolveToken();
          ws.send(JSON.stringify({ type: 'auth', token }));
        } catch (e) {
          this.stopped = true;
          fail(new NexusError('AUTH_FAILED', `Could not obtain token: ${e}`));
          ws.close();
        }
      };

      const authTimer = setTimeout(() => {
        if (!this.authenticated) {
          fail(new NexusError('AUTH_TIMEOUT', 'No auth_ok from SFU'));
          ws.close();
        }
      }, AUTH_TIMEOUT_MS);

      ws.onerror = () => {
        fail(new NexusError('CONNECTION_FAILED', 'WebSocket connection failed'));
      };

      ws.onmessage = (event) => {
        let msg: any;
        try {
          msg = JSON.parse(event.data);
        } catch (e) {
          console.error('Failed to parse message:', e);
          return;
        }

        if (!this.authenticated) {
          if (msg.type === 'auth_ok') {
            clearTimeout(authTimer);
            this.authenticated = true;
            this.reconnectAttempt = 0;
            this.flushQueue();
            this.startPing();
            settled = true;
            this.emit('connected');
            resolve();
          } else if (msg.type === 'error') {
            clearTimeout(authTimer);
            // A rejected token won't succeed on retry
            this.stopped = true;
            fail(new NexusError(msg.code ?? 'AUTH_FAILED', msg.message ?? 'Authentication failed'));
          }
          return;
        }

        this.emit('message', msg as SignalMessage);
      };

      ws.onclose = () => {
        clearTimeout(authTimer);
        this.stopPing();
        this.authenticated = false;
        fail(new NexusError('CONNECTION_FAILED', 'Connection closed before authentication'));
        this.emit('disconnected', { reason: 'connection closed' });
        if (!this.stopped) {
          this.attemptReconnect();
        }
      };
    });
  }

  send(msg: SignalMessage): void {
    if (this.authenticated && this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    } else {
      this.messageQueue.push(msg);
    }
  }

  close(): void {
    this.stopped = true;
    this.stopPing();
    this.ws?.close();
    this.ws = null;
  }

  private async resolveToken(): Promise<string> {
    if (this.token === undefined) {
      throw new Error('no token configured (NexusClientConfig.token)');
    }
    const token = typeof this.token === 'function' ? await this.token() : this.token;
    if (!token) {
      throw new Error('token is empty');
    }
    return token;
  }

  private flushQueue(): void {
    while (this.messageQueue.length > 0) {
      const msg = this.messageQueue.shift()!;
      this.send(msg);
    }
  }

  private attemptReconnect(): void {
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempt), this.maxReconnectDelay);
    this.reconnectAttempt++;

    this.emit('reconnecting', { attempt: this.reconnectAttempt });

    setTimeout(() => {
      if (!this.stopped) {
        this.connect().catch(() => {});
      }
    }, delay);
  }

  private startPing(): void {
    this.pingInterval = window.setInterval(() => {
      this.send({ type: 'Ping' });
    }, 30000);
  }

  private stopPing(): void {
    if (this.pingInterval !== null) {
      clearInterval(this.pingInterval);
      this.pingInterval = null;
    }
  }
}
