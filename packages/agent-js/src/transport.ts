import type { ResolvedConfig } from "./config.js";

/**
 * All event types the browser agent can currently emit. Kept in sync with SPEC §3.1.
 * Server-only event types (`rate_limit_exceeded`, `request_fingerprint`) are still
 * listed here so a single canonical type covers both sources.
 */
export type EventType =
  | "honeypot_triggered"
  | "canary_embedded"
  | "rate_limit_exceeded"
  | "behavioral_score"
  | "attestation_failed"
  | "request_fingerprint";

/**
 * Wire format for events sent to the reporting API. Matches SPEC §3.1 exactly.
 * Browser-sourced events always have `ip_hash: null` and `asn: null` — those are
 * populated server-side from the request context, never by the client.
 */
export interface EventPayload {
  event_id: string;
  site_id: string;
  timestamp: string;
  source: "browser";
  session_id: string;
  type: EventType;
  score_delta: number;
  details: Record<string, unknown>;
  ip_hash: null;
  user_agent: string;
  asn: null;
}

/**
 * RFC 4122 v4 UUID. Prefers `crypto.randomUUID()` (available everywhere modern);
 * falls back to a manual construction using `crypto.getRandomValues` for older
 * WebViews. Math.random path is last-resort only.
 */
export function uuidv4(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  const bytes = new Uint8Array(16);
  if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
    crypto.getRandomValues(bytes);
  } else {
    for (let i = 0; i < 16; i++) bytes[i] = Math.floor(Math.random() * 256);
  }
  // Set version (4) and variant (10xx) bits per RFC 4122
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex: string[] = [];
  for (let i = 0; i < 16; i++) hex.push(bytes[i].toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex.slice(6, 8).join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10, 16).join("")}`;
}

export interface Transport {
  /** Fire-and-forget send. Never throws, never blocks, never emits console.error. */
  send: (type: EventType, scoreDelta: number, details: Record<string, unknown>) => void;
  /** Directly construct the wire payload for a given event. Exposed for testing. */
  buildPayload: (
    type: EventType,
    scoreDelta: number,
    details: Record<string, unknown>,
  ) => EventPayload;
}

/**
 * Build a transport bound to a resolved config and session ID.
 *
 * Fail-silent contract:
 *  - No code path from `send()` will throw. Ever. Serialization errors, network errors,
 *    absent globals — all swallowed.
 *  - No `console.error` from this module.
 *  - A single `console.warn` may fire, gated by `config.debug`.
 *  - Uses `navigator.sendBeacon` when available (browsers queue and flush these even during
 *    page unload) with `fetch({ keepalive: true })` as fallback. Neither blocks the main
 *    thread.
 */
export function createTransport(config: ResolvedConfig, sessionId: string): Transport {
  const url = `${config.endpoint}/api/v1/events`;

  function buildPayload(
    type: EventType,
    scoreDelta: number,
    details: Record<string, unknown>,
  ): EventPayload {
    return {
      event_id: uuidv4(),
      site_id: config.siteId,
      timestamp: new Date().toISOString(),
      source: "browser",
      session_id: sessionId,
      type,
      score_delta: scoreDelta,
      details,
      ip_hash: null,
      user_agent: typeof navigator !== "undefined" ? navigator.userAgent : "",
      asn: null,
    };
  }

  function send(
    type: EventType,
    scoreDelta: number,
    details: Record<string, unknown>,
  ): void {
    let body: string;
    try {
      const payload = buildPayload(type, scoreDelta, details);
      body = JSON.stringify(payload);
    } catch {
      // Details contained something un-serializable (circular ref, BigInt, etc).
      // Nothing to send; nothing to raise.
      return;
    }

    try {
      // Preferred path: sendBeacon. Browser queues the request and flushes it even if the
      // page is unloading, without blocking the main thread. Returns false if the beacon
      // queue is full — we deliberately don't retry, per fail-silent policy.
      if (
        typeof navigator !== "undefined" &&
        typeof navigator.sendBeacon === "function"
      ) {
        try {
          const blob = new Blob([body], { type: "application/json" });
          navigator.sendBeacon(url, blob);
          return;
        } catch {
          // fall through to fetch
        }
      }

      if (typeof fetch === "function") {
        // keepalive: true lets the request survive page unload.
        // credentials: 'omit' avoids CORS preflight complications and prevents accidental
        // cookie leakage to the reporting API (which never needs them).
        fetch(url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body,
          keepalive: true,
          credentials: "omit",
          mode: "cors",
        }).catch(() => {
          if (config.debug) {
            // eslint-disable-next-line no-console
            console.warn("[ReverseShield] transport fetch failed (silenced)");
          }
        });
      }
    } catch {
      // Absolute last-resort catch: if `navigator.sendBeacon` or `fetch` itself throws
      // synchronously (some sandboxed contexts do this), swallow.
    }
  }

  return { send, buildPayload };
}
