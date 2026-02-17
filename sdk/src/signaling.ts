import { SignalMessage } from './messages';
import { EventEmitter } from './events';
import { NexusError } from './errors';

export class SignalingTransport extends EventEmitter {
  private ws: WebSocket | null = null;
  private reconnectAttempt = 0;
  private maxReconnectDelay = 30000;
  private messageQueue: SignalMessage[] = [];
  private pingInterval: number | null = null;

  constructor(private url: string) {
    super();
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.url);
      
      this.ws.onopen = () => {
        this.reconnectAttempt = 0;
        this.flushQueue();
        this.startPing();
        this.emit('connected');
        resolve();
      };

      this.ws.onerror = (err) => {
        reject(new NexusError('CONNECTION_FAILED', 'WebSocket connection failed'));
      };

      this.ws.onmessage = (event) => {
        try {
          const msg: SignalMessage = JSON.parse(event.data);
          this.emit('message', msg);
        } catch (e) {
          console.error('Failed to parse message:', e);
        }
      };

      this.ws.onclose = () => {
        this.stopPing();
        this.emit('disconnected', { reason: 'connection closed' });
        this.attemptReconnect();
      };
    });
  }

  send(msg: SignalMessage): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    } else {
      this.messageQueue.push(msg);
    }
  }

  close(): void {
    this.stopPing();
    this.ws?.close();
    this.ws = null;
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
      this.connect().catch(() => {});
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
