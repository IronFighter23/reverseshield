/**
 * WebAssembly-backed local scoring for the ReverseShield browser agent.
 *
 * Contract: never crashes the host site. Every failure path — network error, non-2xx
 * rules response, malformed rules JSON, missing WASM binary, WASM init throw, runtime
 * scoring exception — returns null. The agent's event pipeline keeps running with or
 * without a scorer; local scoring is a lazy upgrade, not a hard dependency.
 *
 * Bundle-size discipline: this file statically imports the wasm-bindgen JS glue, which
 * adds ~3 KB gzipped to the main bundle. The actual .wasm binary is fetched at runtime
 * via `init(url)`, so page-load payload stays under the initial-JS budget. The CI
 * workflow enforces both ceilings (dist/index.js gzipped ≤ 12 KB, .wasm gzipped ≤ 60 KB).
 *
 * See packages/core/src/wasm.rs for the Rust side of this contract.
 */

import init, { scoreFromWeights, scoreSignalsJson } from "./wasm/reverseshield_core.js";
import type { ResolvedConfig } from "./config.js";

/** Mirror of the Rust `ScoreResult` struct — see packages/core/src/scoring.rs. */
export interface ScoreResult {
  score: number;
  band: "likely_human" | "suspicious" | "likely_bot";
  triggered_rule_ids: string[];
  total_weight: number;
}

export interface Scorer {
  /**
   * Score a list of event signals against the rule set fetched at init time.
   * Returns null if scoring fails at runtime. This is the "silent" half of
   * silent-fail — callers treat null as "score unavailable this call" and continue.
   */
  score(signals: string[]): ScoreResult | null;
  /**
   * Bare weights → clamped score (0-100). Useful when the caller already knows the
   * weights that triggered (e.g. from a cached prior computation). Returns null on
   * failure.
   */
  scoreWeights(weights: number[]): number | null;
}

// Module-level state. Guarantees `initScoring` is called at most once per page load:
// the caching lives here rather than inside the JS agent's init() so any consumer
// (attestation logic in v2, etc.) can call `initScoring(resolved)` and get the same
// promise back without triggering a second network round-trip.
let initPromise: Promise<Scorer | null> | null = null;

/**
 * Load the WASM scoring engine and fetch the rule set. Returns null on any failure.
 * Idempotent — subsequent calls in the same page return the same Scorer or the same
 * null. Never throws.
 */
export function initScoring(config: ResolvedConfig): Promise<Scorer | null> {
  if (initPromise !== null) return initPromise;
  initPromise = doInit(config);
  return initPromise;
}

/** Test-only escape hatch to reset the module-level cache between test cases. */
export function __resetScoringForTests(): void {
  initPromise = null;
}

async function doInit(config: ResolvedConfig): Promise<Scorer | null> {
  try {
    const rulesJson = await fetchRules(config);
    if (rulesJson === null) return null;

    // wasm-bindgen's `--target web` init() accepts a URL string, a Response, a
    // Uint8Array, or a WebAssembly.Module. Passing the URL is simplest — the browser
    // uses `WebAssembly.instantiateStreaming` under the hood for best performance.
    await init(config.wasmUrl);

    return {
      score(signals: string[]): ScoreResult | null {
        try {
          const raw = scoreSignalsJson(rulesJson, JSON.stringify(signals));
          return JSON.parse(raw) as ScoreResult;
        } catch (err) {
          warn(config, "score() failed at runtime", err);
          return null;
        }
      },
      scoreWeights(weights: number[]): number | null {
        try {
          return scoreFromWeights(Uint32Array.from(weights));
        } catch (err) {
          warn(config, "scoreWeights() failed at runtime", err);
          return null;
        }
      },
    };
  } catch (err) {
    warn(config, "initScoring failed (silenced)", err);
    return null;
  }
}

async function fetchRules(config: ResolvedConfig): Promise<string | null> {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), config.rulesTimeoutMs);
    try {
      const response = await fetch(config.rulesUrl, { signal: controller.signal });
      if (!response.ok) {
        warn(config, `rules fetch returned status ${response.status}`);
        return null;
      }
      const text = await response.text();
      // Verify the response actually parses as JSON before handing it to the WASM
      // boundary. A wrong Content-Type from a misconfigured server would otherwise
      // blow up inside the Rust `serde_json::from_str` with a much less legible error.
      JSON.parse(text);
      return text;
    } finally {
      clearTimeout(timeoutId);
    }
  } catch (err) {
    warn(config, "rules fetch failed", err);
    return null;
  }
}

function warn(config: ResolvedConfig, message: string, err?: unknown): void {
  if (!config.debug) return;
  // eslint-disable-next-line no-console
  console.warn(`[ReverseShield] ${message}`, err);
}
