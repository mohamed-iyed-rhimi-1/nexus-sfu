// ============================================================================
// Nexus SDK — Typed Event Emitter
// Zero dependencies. Type-safe event map.
// ============================================================================

type Handler<T> = (data: T) => void;

/**
 * Typed event emitter. Events and their payload types are defined
 * by the generic parameter `E` (a record of event name → payload type).
 */
export class EventEmitter<E extends object = Record<string, unknown>> {
  private listeners = new Map<keyof E, Set<Handler<never>>>();

  /** Register a handler for an event. */
  on<K extends keyof E>(event: K, handler: Handler<E[K]>): void {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(handler as Handler<never>);
  }

  /** Remove a handler. */
  off<K extends keyof E>(event: K, handler: Handler<E[K]>): void {
    this.listeners.get(event)?.delete(handler as Handler<never>);
  }

  /** Remove all handlers for an event, or all handlers if no event given. */
  removeAll(event?: keyof E): void {
    if (event) {
      this.listeners.delete(event);
    } else {
      this.listeners.clear();
    }
  }

  /** Emit an event to all registered handlers. */
  protected emit<K extends keyof E>(event: K, data: E[K]): void {
    const set = this.listeners.get(event);
    if (!set) return;
    for (const handler of set) {
      try {
        (handler as Handler<E[K]>)(data);
      } catch (err) {
        console.error(`[nexus-sdk] Error in ${String(event)} handler:`, err);
      }
    }
  }
}
