// ============================================================================
// Nexus SDK — Viewport Manager
// Uses IntersectionObserver to track which <video> elements are visible,
// then sends Viewport messages to the SFU so it can skip forwarding
// off-screen video tracks. Debounced to avoid flooding.
// ============================================================================

import type { Signaling } from './signaling.js';

const DEBOUNCE_MS = 200;

/**
 * Viewport manager. Watches attached video elements and automatically
 * sends Viewport updates to the SFU when visibility changes.
 */
export class ViewportManager {
  private signaling: Signaling;
  private observer: IntersectionObserver | null = null;
  /** element → participant ID */
  private tracked = new Map<Element, number>();
  /** Currently visible participant IDs. */
  private visible = new Set<number>();
  /** Manually pinned participant IDs (always receive video). */
  private pinned = new Set<number>();
  private debounceTimer: ReturnType<typeof setTimeout> | null = null;
  private enabled = true;

  constructor(signaling: Signaling) {
    this.signaling = signaling;

    if (typeof IntersectionObserver !== 'undefined') {
      this.observer = new IntersectionObserver(
        (entries) => this.handleIntersection(entries),
        { threshold: 0.1 }, // 10% visible = "in viewport"
      );
    }
  }

  /**
   * Watch a DOM element. When it enters/leaves the viewport,
   * the participant's video will be included/excluded.
   */
  watch(element: Element, participantId: number): void {
    this.tracked.set(element, participantId);
    this.observer?.observe(element);
  }

  /** Stop watching an element. */
  unwatch(element: Element): void {
    this.observer?.unobserve(element);
    const pid = this.tracked.get(element);
    this.tracked.delete(element);
    if (pid !== undefined) {
      this.visible.delete(pid);
      this.scheduleUpdate();
    }
  }

  /** Pin a participant — always receive their video regardless of viewport. */
  pin(participantId: number): void {
    this.pinned.add(participantId);
    this.scheduleUpdate();
  }

  /** Unpin a participant. */
  unpin(participantId: number): void {
    this.pinned.delete(participantId);
    this.scheduleUpdate();
  }

  /** Enable/disable viewport tracking. When disabled, sends empty viewport (= forward all). */
  setEnabled(enabled: boolean): void {
    this.enabled = enabled;
    this.sendUpdate();
  }

  /** Clean up observer and timers. */
  destroy(): void {
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    this.observer?.disconnect();
    this.tracked.clear();
    this.visible.clear();
    this.pinned.clear();
  }

  // -------------------------------------------------------------------------
  // Internal
  // -------------------------------------------------------------------------

  private handleIntersection(entries: IntersectionObserverEntry[]): void {
    for (const entry of entries) {
      const pid = this.tracked.get(entry.target);
      if (pid === undefined) continue;

      if (entry.isIntersecting) {
        this.visible.add(pid);
      } else {
        this.visible.delete(pid);
      }
    }
    this.scheduleUpdate();
  }

  private scheduleUpdate(): void {
    if (this.debounceTimer) clearTimeout(this.debounceTimer);
    this.debounceTimer = setTimeout(() => this.sendUpdate(), DEBOUNCE_MS);
  }

  private sendUpdate(): void {
    if (!this.enabled) {
      // Empty = forward everything
      this.signaling.send({ type: 'Viewport', visible: [], pinned: [] });
      return;
    }

    this.signaling.send({
      type: 'Viewport',
      visible: [...this.visible],
      pinned: [...this.pinned],
    });
  }
}
