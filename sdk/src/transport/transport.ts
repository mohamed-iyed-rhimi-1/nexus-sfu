// ============================================================================
// Nexus SDK — Signaling Transport Interface
// ============================================================================

export type TransportState = 'connecting' | 'open' | 'closing' | 'closed';

/**
 * Abstract signaling transport. Implemented by WebSocket and WebTransport.
 * All signaling messages flow through this interface.
 */
export interface SignalingTransport {
  /** Connect to the server. Resolves when the connection is open. */
  connect(url: string, protocols?: string[]): Promise<void>;

  /** Send a text or binary message. Throws if not open. */
  send(data: string | Uint8Array): void;

  /** Register the message handler. Only one handler at a time. */
  onMessage(handler: (data: string | Uint8Array) => void): void;

  /** Register the close handler. */
  onClose(handler: (code: number, reason: string) => void): void;

  /** Gracefully close the connection. */
  close(code?: number, reason?: string): void;

  /** Current connection state. */
  readonly state: TransportState;
}
