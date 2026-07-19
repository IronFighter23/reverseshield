/**
 * Silent-fail contract tests for scoring.ts.
 *
 * Every failure path the WASM loader can encounter is tested here with mocks —
 * network timeouts, 404s, 500s, malformed JSON, WASM init throwing, WASM scoring
 * throwing at runtime. The one non-negotiable invariant across all of these:
 * initScoring returns null and Scorer.score returns null. Nothing throws. Nothing
 * crashes the host page. Nothing calls console.error. If debug is on, exactly one
 * console.warn per failure gets emitted; if debug is off, silence.
 *
 * Real WASM behavior lives in scoring.wasm.test.ts — that file loads the actual
 * compiled binary and asserts scoring correctness. This file only cares about the
 * error-handling wrapper.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// Mock the wasm-bindgen glue module BEFORE importing scoring.ts. `vi.mock` factories
// are hoisted above module-scope declarations, so the spies they reference must live
// inside `vi.hoisted()` (which is also hoisted). This is the canonical vitest pattern
// for "mocked import that a test can reconfigure per case".
const { mockInit, mockScoreFromWeights, mockScoreSignalsJson } = vi.hoisted(() => ({
  mockInit: vi.fn<(input?: unknown) => Promise<unknown>>(),
  mockScoreFromWeights: vi.fn<(weights: Uint32Array) => number>(),
  mockScoreSignalsJson: vi.fn<(rulesJson: string, signalsJson: string) => string>(),
}));

vi.mock("../src/wasm/reverseshield_core.js", () => ({
  default: mockInit,
  scoreFromWeights: mockScoreFromWeights,
  scoreSignalsJson: mockScoreSignalsJson,
}));

import { initScoring, __resetScoringForTests } from "../src/scoring.js";
import type { ResolvedConfig } from "../src/config.js";

const RULES_JSON = JSON.stringify([
  { id: "honeypot-field-fill", description: "h", signal: "honeypot_triggered", weight: 80, action: "flag" },
  { id: "rate-limit-exceeded", description: "r", signal: "rate_limit_exceeded", weight: 40, action: "flag" },
]);

const SCORE_RESULT_JSON = JSON.stringify({
  score: 20,
  band: "likely_bot",
  triggered_rule_ids: ["honeypot-field-fill"],
  total_weight: 80,
});

function makeConfig(overrides: Partial<ResolvedConfig> = {}): ResolvedConfig {
  return {
    siteId: "test-site",
    endpoint: "https://reporting.example.com",
    seed: "rs-seed-test-site",
    honeypotCount: 2,
    debug: false,
    behavioralSnapshotDelayMs: 10_000,
    localScoring: true,
    rulesUrl: "https://reporting.example.com/api/v1/sites/test-site/rules.json",
    wasmUrl: "https://reporting.example.com/agent/reverseshield_core_bg.wasm",
    rulesTimeoutMs: 5_000,
    ...overrides,
  };
}

/**
 * Build a `fetch` stub that emulates one of several failure modes. The point of a
 * shared helper is to make each test read as "fetch does X → initScoring returns
 * null" without repeating a Response constructor per case.
 */
function stubFetch(mode:
  | { kind: "ok"; body: string }
  | { kind: "status"; status: number }
  | { kind: "throw"; err: Error }
  | { kind: "abort" }
): void {
  vi.stubGlobal("fetch", vi.fn((_url: string, init?: RequestInit) => {
    if (mode.kind === "throw") return Promise.reject(mode.err);
    if (mode.kind === "abort") {
      // Simulate a real abort: return a promise that rejects when the signal fires.
      return new Promise((_, reject) => {
        init?.signal?.addEventListener("abort", () => {
          reject(new DOMException("aborted", "AbortError"));
        });
      });
    }
    if (mode.kind === "status") {
      return Promise.resolve({ ok: false, status: mode.status, text: () => Promise.resolve("") } as Response);
    }
    return Promise.resolve({ ok: true, status: 200, text: () => Promise.resolve(mode.body) } as Response);
  }));
}

// -----------------------------------------------------------------------------
// Silent-fail failure paths — the whole point of the wrapper.
// -----------------------------------------------------------------------------

describe("initScoring — silent-fail contract", () => {
  beforeEach(() => {
    __resetScoringForTests();
    mockInit.mockReset();
    mockScoreFromWeights.mockReset();
    mockScoreSignalsJson.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns null when rules fetch rejects (network error)", async () => {
    stubFetch({ kind: "throw", err: new TypeError("Failed to fetch") });
    const result = await initScoring(makeConfig());
    expect(result).toBeNull();
    // WASM init must not have been called — the loader short-circuited before it.
    expect(mockInit).not.toHaveBeenCalled();
  });

  it("returns null when rules endpoint returns 404", async () => {
    stubFetch({ kind: "status", status: 404 });
    const result = await initScoring(makeConfig());
    expect(result).toBeNull();
    expect(mockInit).not.toHaveBeenCalled();
  });

  it("returns null when rules endpoint returns 500", async () => {
    stubFetch({ kind: "status", status: 500 });
    const result = await initScoring(makeConfig());
    expect(result).toBeNull();
    expect(mockInit).not.toHaveBeenCalled();
  });

  it("returns null when rules body is malformed JSON", async () => {
    stubFetch({ kind: "ok", body: "not-json-at-all[[[" });
    const result = await initScoring(makeConfig());
    expect(result).toBeNull();
    expect(mockInit).not.toHaveBeenCalled();
  });

  it("returns null when rules fetch times out", async () => {
    stubFetch({ kind: "abort" });
    // Use a 10ms timeout so the test doesn't wait 5 seconds.
    const result = await initScoring(makeConfig({ rulesTimeoutMs: 10 }));
    expect(result).toBeNull();
    expect(mockInit).not.toHaveBeenCalled();
  });

  it("returns null when WASM init throws (missing/bad .wasm)", async () => {
    stubFetch({ kind: "ok", body: RULES_JSON });
    mockInit.mockRejectedValueOnce(new Error("wasm not built"));
    const result = await initScoring(makeConfig());
    expect(result).toBeNull();
  });
});

// -----------------------------------------------------------------------------
// Happy path — mocked WASM produces a Scorer that behaves per contract.
// -----------------------------------------------------------------------------

describe("initScoring — happy path with mocked WASM", () => {
  beforeEach(() => {
    __resetScoringForTests();
    mockInit.mockReset();
    mockScoreFromWeights.mockReset();
    mockScoreSignalsJson.mockReset();
    stubFetch({ kind: "ok", body: RULES_JSON });
    mockInit.mockResolvedValueOnce(undefined);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns a Scorer whose score() forwards signals to WASM and parses the JSON result", async () => {
    mockScoreSignalsJson.mockReturnValueOnce(SCORE_RESULT_JSON);
    const scorer = await initScoring(makeConfig());
    expect(scorer).not.toBeNull();

    const out = scorer!.score(["honeypot_triggered"]);
    expect(out).toEqual({
      score: 20,
      band: "likely_bot",
      triggered_rule_ids: ["honeypot-field-fill"],
      total_weight: 80,
    });
    // Confirm we passed rules + signals through in the right shape.
    expect(mockScoreSignalsJson).toHaveBeenCalledWith(
      RULES_JSON,
      JSON.stringify(["honeypot_triggered"]),
    );
  });

  it("Scorer.score() returns null and does not throw when WASM throws at runtime", async () => {
    mockScoreSignalsJson.mockImplementationOnce(() => {
      throw new Error("wasm scoring blew up");
    });
    const scorer = await initScoring(makeConfig());
    expect(scorer!.score(["honeypot_triggered"])).toBeNull();
  });

  it("Scorer.scoreWeights() forwards to WASM and returns the number", async () => {
    mockScoreFromWeights.mockReturnValueOnce(20);
    const scorer = await initScoring(makeConfig());
    expect(scorer!.scoreWeights([80])).toBe(20);
    // Uint32Array conversion happens in scoring.ts — the arg WASM sees is typed.
    const arg = mockScoreFromWeights.mock.calls[0]![0];
    expect(arg).toBeInstanceOf(Uint32Array);
    expect(Array.from(arg)).toEqual([80]);
  });

  it("Scorer.scoreWeights() returns null and does not throw when WASM throws", async () => {
    mockScoreFromWeights.mockImplementationOnce(() => {
      throw new Error("wasm score blew up");
    });
    const scorer = await initScoring(makeConfig());
    expect(scorer!.scoreWeights([80])).toBeNull();
  });
});

// -----------------------------------------------------------------------------
// Behaviors that don't fit "fail" or "happy" cleanly.
// -----------------------------------------------------------------------------

describe("initScoring — cross-cutting behaviors", () => {
  beforeEach(() => {
    __resetScoringForTests();
    mockInit.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("is idempotent — repeated calls return the same promise (no double fetch, no double init)", async () => {
    stubFetch({ kind: "ok", body: RULES_JSON });
    mockInit.mockResolvedValueOnce(undefined);

    const first = initScoring(makeConfig());
    const second = initScoring(makeConfig());
    expect(first).toBe(second);

    await Promise.all([first, second]);
    // Assert fetch was called exactly once — the whole point of caching the promise
    // is that a second caller doesn't trigger a second round trip.
    expect((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.length).toBe(1);
    expect(mockInit.mock.calls.length).toBe(1);
  });

  it("caches even the null result — a failed init is not retried within a session", async () => {
    stubFetch({ kind: "status", status: 500 });
    const first = await initScoring(makeConfig());
    const second = await initScoring(makeConfig());
    expect(first).toBeNull();
    expect(second).toBeNull();
    // Confirms the "null is cached too" invariant — otherwise a 5xx would retry every
    // time score() is polled, hammering a broken reporting service.
    expect((globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls.length).toBe(1);
  });

  it("emits console.warn only when config.debug is true", async () => {
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    stubFetch({ kind: "status", status: 500 });

    await initScoring(makeConfig({ debug: false }));
    expect(warnSpy).not.toHaveBeenCalled();

    __resetScoringForTests();
    await initScoring(makeConfig({ debug: true }));
    expect(warnSpy).toHaveBeenCalled();

    warnSpy.mockRestore();
  });

  it("never throws even when config-driven URLs are junk", async () => {
    // Belt-and-braces: even if the app somehow ends up with a garbage URL that
    // fetch itself rejects synchronously (some browsers do this for scheme errors),
    // initScoring must not propagate.
    vi.stubGlobal("fetch", vi.fn(() => {
      throw new TypeError("scheme not supported");
    }));
    const result = await initScoring(makeConfig({ rulesUrl: "not-a-url" }));
    expect(result).toBeNull();
  });
});
