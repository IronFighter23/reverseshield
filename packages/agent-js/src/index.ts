/**
 * ReverseShield browser agent — public entry point.
 *
 * Usage:
 *   import { init } from '@reverseshield/agent';
 *   init({ siteId: '...', endpoint: 'https://reporting.example.com' });
 *
 * Guarantees:
 *  - Safe to call in SSR contexts (no-op if window/document absent).
 *  - Safe to call multiple times — subsequent calls are ignored.
 *  - Config validation errors (missing siteId/endpoint) throw synchronously so a
 *    developer sees the mistake immediately. All runtime failures — DOM manipulation,
 *    transport, telemetry — are swallowed.
 */

import { type Config, resolveConfig } from "./config.js";
import { installHoneypots } from "./honeypot.js";
import { generateCanaryToken, embedCanaryToken } from "./canary.js";
import { startTelemetry } from "./telemetry.js";
import { createTransport, uuidv4 } from "./transport.js";

let initialized = false;

/**
 * Initialize the ReverseShield browser agent.
 *
 * @throws only on invalid config (missing/malformed siteId or endpoint). All other
 *         failures are swallowed; if `debug: true`, they emit a single `console.warn`.
 */
export function init(config: Config): void {
  // Config resolution can throw — that's intentional (dev error, not runtime error).
  // We do NOT wrap this in try/catch, because silently swallowing a bad config would
  // leave the developer wondering why nothing works.
  const resolved = resolveConfig(config);

  try {
    if (initialized) return;
    initialized = true;

    if (typeof window === "undefined" || typeof document === "undefined") {
      return; // SSR / non-browser context — nothing to do
    }

    const sessionId = uuidv4();
    const transport = createTransport(resolved, sessionId);

    const ready = (): void => {
      try {
        // 1. Honeypots
        installHoneypots(resolved, (fieldName) => {
          transport.send("honeypot_triggered", -80, { field: fieldName });
        });

        // 2. Canary token
        const token = generateCanaryToken(resolved.siteId);
        embedCanaryToken(token);
        transport.send("canary_embedded", 0, { token });

        // 3. Behavioral telemetry
        const telemetry = startTelemetry();
        const flushTelemetry = (): void => {
          // Wrap the snapshot under a `snapshot` key rather than spreading its fields
          // directly into details. Keeps the wire event self-documenting and avoids
          // a TS strict-index-signature quirk with the BehavioralSnapshot interface.
          transport.send("behavioral_score", 0, { snapshot: telemetry.snapshot() });
        };
        setTimeout(flushTelemetry, resolved.behavioralSnapshotDelayMs);
        // pagehide is more reliable than beforeunload on mobile Safari
        window.addEventListener("pagehide", flushTelemetry, { once: true });
      } catch (err) {
        if (resolved.debug) {
          // eslint-disable-next-line no-console
          console.warn("[ReverseShield] setup failed (silenced)", err);
        }
      }
    };

    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", ready, { once: true });
    } else {
      ready();
    }
  } catch (err) {
    // Belt-and-braces: even the wiring above shouldn't be able to throw, but if it does,
    // we still refuse to crash the host page.
    if (resolved.debug) {
      // eslint-disable-next-line no-console
      console.warn("[ReverseShield] init failed (silenced)", err);
    }
  }
}

// Test-only escape hatch. Not exported from package.json; here for the unit tests to
// reset internal state between cases. Do NOT rely on this in application code.
export function __resetForTests(): void {
  initialized = false;
}

export type { Config, ResolvedConfig } from "./config.js";
export type { EventType, EventPayload } from "./transport.js";
export type { BehavioralSnapshot } from "./telemetry.js";

export default { init };
