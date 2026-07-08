/**
 * Passive behavioral telemetry.
 *
 * Design choices:
 *  - We only collect coarse counts and one derived metric (mouse distance). Deciding
 *    what constitutes bot-like behavior belongs in `packages/core` (see SPEC §4.C), not
 *    here — this module just emits raw signal.
 *  - All listeners are `passive: true` so scrolling and mouse movement stay 60fps even
 *    on low-end devices. We're building a defense agent, not a performance regression.
 *  - We do NOT persist anything to localStorage / cookies / IndexedDB. Session data is
 *    in-memory only. Persistence introduces GDPR / cookie-banner surface area that v1
 *    doesn't need.
 */

export interface BehavioralSnapshot {
  /** Total mousemove events observed. */
  mouseMoves: number;
  /** Cumulative Euclidean distance of mouse motion in CSS pixels, rounded. */
  mouseDistance: number;
  /** Total scroll events observed. */
  scrollEvents: number;
  /** Total keydown events observed. */
  keyPresses: number;
  /** Total click events observed. */
  clickCount: number;
  /** Milliseconds from `startTelemetry()` call to first interaction, or null if none. */
  timeToFirstInteractionMs: number | null;
  /** Milliseconds from `startTelemetry()` to snapshot moment. */
  durationMs: number;
}

export interface TelemetryHandle {
  snapshot: () => BehavioralSnapshot;
  stop: () => void;
}

/**
 * Start collecting behavioral signals. Safe to call in SSR contexts — if `window` is
 * absent, returns a no-op handle that always reports zeros.
 *
 * @throws never
 */
export function startTelemetry(): TelemetryHandle {
  const startedAt = Date.now();
  let mouseMoves = 0;
  let mouseDistance = 0;
  let scrollEvents = 0;
  let keyPresses = 0;
  let clickCount = 0;
  let firstInteractionAt: number | null = null;
  let lastX: number | null = null;
  let lastY: number | null = null;

  const emptySnapshot = (): BehavioralSnapshot => ({
    mouseMoves: 0,
    mouseDistance: 0,
    scrollEvents: 0,
    keyPresses: 0,
    clickCount: 0,
    timeToFirstInteractionMs: null,
    durationMs: Date.now() - startedAt,
  });

  if (typeof window === "undefined") {
    return { snapshot: emptySnapshot, stop: () => undefined };
  }

  const markFirst = (): void => {
    if (firstInteractionAt === null) firstInteractionAt = Date.now();
  };

  const onMove = (e: MouseEvent): void => {
    mouseMoves++;
    if (lastX !== null && lastY !== null) {
      mouseDistance += Math.hypot(e.clientX - lastX, e.clientY - lastY);
    }
    lastX = e.clientX;
    lastY = e.clientY;
    markFirst();
  };
  const onScroll = (): void => {
    scrollEvents++;
    markFirst();
  };
  const onKey = (): void => {
    keyPresses++;
    markFirst();
  };
  const onClick = (): void => {
    clickCount++;
    markFirst();
  };

  try {
    window.addEventListener("mousemove", onMove, { passive: true });
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("keydown", onKey, { passive: true });
    window.addEventListener("click", onClick, { passive: true });
  } catch {
    // Some sandboxed iframes throw on addEventListener; degrade to no-op.
    return { snapshot: emptySnapshot, stop: () => undefined };
  }

  return {
    snapshot(): BehavioralSnapshot {
      return {
        mouseMoves,
        mouseDistance: Math.round(mouseDistance),
        scrollEvents,
        keyPresses,
        clickCount,
        timeToFirstInteractionMs:
          firstInteractionAt === null ? null : firstInteractionAt - startedAt,
        durationMs: Date.now() - startedAt,
      };
    },
    stop(): void {
      try {
        window.removeEventListener("mousemove", onMove);
        window.removeEventListener("scroll", onScroll);
        window.removeEventListener("keydown", onKey);
        window.removeEventListener("click", onClick);
      } catch {
        // ignore
      }
    },
  };
}
