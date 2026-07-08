/**
 * Public configuration surface for the ReverseShield browser agent.
 *
 * Design notes:
 *  - `siteId` and `endpoint` are the only truly required fields. Everything else has a
 *    safe default so a site owner can call `init({ siteId, endpoint })` and get a working
 *    v1 install.
 *  - `seed` defaults to a derivation of `siteId`. It only needs to be set explicitly when
 *    you want to rotate honeypot field names without re-issuing the `siteId` (e.g. after
 *    a batch of names has been publicly footprinted).
 *  - We deliberately do NOT accept a "disable telemetry" flag in v1 — if you're installing
 *    a defense agent, you want the signals. v2 can add granular toggles once we know which
 *    ones site owners actually want to turn off.
 */
export interface Config {
  /** Site UUID returned by the reporting API when the site was registered. */
  siteId: string;
  /** Reporting API base URL, e.g. `https://reporting.example.com`. Trailing slashes stripped. */
  endpoint: string;
  /**
   * Optional per-site seed used to derive honeypot field names and any other randomized
   * identifiers. Defaults to a derivation of `siteId`. Rotate this to force new honeypot
   * names without changing `siteId`.
   */
  seed?: string;
  /** Number of hidden honeypot fields to inject. Default: 2. */
  honeypotCount?: number;
  /**
   * If true, transport and init failures emit `console.warn` (never `console.error`,
   * never a thrown exception). Default: false.
   */
  debug?: boolean;
  /** Milliseconds after DOM ready to send the first behavioral snapshot. Default: 10000. */
  behavioralSnapshotDelayMs?: number;
}

/** Fully-resolved config used internally. All fields required. */
export interface ResolvedConfig {
  siteId: string;
  endpoint: string;
  seed: string;
  honeypotCount: number;
  debug: boolean;
  behavioralSnapshotDelayMs: number;
}

/**
 * Validate + normalize a user-supplied config.
 * Throws only on developer errors (missing required fields) — those should be caught
 * immediately in dev, not swallowed silently. Transport failures at runtime are the
 * things that must never throw; misconfiguration is a different category.
 */
export function resolveConfig(input: Config): ResolvedConfig {
  if (!input || typeof input !== "object") {
    throw new Error("ReverseShield: config object is required");
  }
  if (!input.siteId || typeof input.siteId !== "string") {
    throw new Error("ReverseShield: config.siteId is required and must be a string");
  }
  if (!input.endpoint || typeof input.endpoint !== "string") {
    throw new Error("ReverseShield: config.endpoint is required and must be a string");
  }

  const honeypotCount = input.honeypotCount ?? 2;
  if (!Number.isInteger(honeypotCount) || honeypotCount < 0 || honeypotCount > 10) {
    throw new Error("ReverseShield: config.honeypotCount must be an integer between 0 and 10");
  }

  const behavioralSnapshotDelayMs = input.behavioralSnapshotDelayMs ?? 10_000;
  if (!Number.isFinite(behavioralSnapshotDelayMs) || behavioralSnapshotDelayMs < 0) {
    throw new Error("ReverseShield: config.behavioralSnapshotDelayMs must be a non-negative number");
  }

  return {
    siteId: input.siteId,
    endpoint: input.endpoint.replace(/\/+$/, ""),
    seed: input.seed ?? `rs-seed-${input.siteId}`,
    honeypotCount,
    debug: input.debug ?? false,
    behavioralSnapshotDelayMs,
  };
}
